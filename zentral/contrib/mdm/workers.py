from datetime import datetime
import logging
from django.db import connection
import psycopg2.extras
from zentral.utils.leaky_bucket import LeakyBucket
from zentral.conf import settings
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.queues import queues
from .apns import apns_client_cache
from .events import post_mdm_device_notification_event


logger = logging.getLogger("zentral.contrib.mdm.workers")


class BaseAPNSWorker:
    apns_priority = 10  # TODO hard coded. Verify.
    counter_name = "apns_notification_sent"

    def __init__(self):
        apns_conf = settings["apps"]["zentral.contrib.mdm"].get("apns", {})
        connect_conf = apns_conf.get("connect", {})
        workers_conf = apns_conf.get("workers", {})

        # query parameters
        self.kwargs = {}
        try:
            # minimum target age: 5s by default (min 1s, max 2min)
            self.kwargs["min_target_age"] = min(max(1, int(apns_conf.get("min_target_age", 5))), 120)
        except (TypeError, ValueError):
            raise ImproperlyConfigured("APNS minimum target age must be an integer")
        try:
            # acquire batches of 50 targets by default (min 1, max 1000)
            self.kwargs["batch_size"] = min(max(1, int(workers_conf.get("batch_size", 50))), 1000)
            # after 120 seconds by default, targets can be acquired by other workers (min 10s max 10min)
            self.kwargs["timeout"] = min(max(10, int(workers_conf.get("visibility_timeout", 120))), 600)
        except (TypeError, ValueError):
            raise ImproperlyConfigured("APNS workers batch size and visibility timeout must be integers")
        try:
            # default connect period: 4h (min 1min, max 7d)
            self.kwargs["default_period"] = min(max(60, int(connect_conf.get("default_period", 14400))), 604800)
            # default time to wait before notifying again if no connect: 1d (min 10m, max 7d)
            self.kwargs["retry_delay"] = min(max(600, int(connect_conf.get("retry_delay", 86400))), 604800)
            # default time to wait before notifying again if new target: 30s (min 10s, max 1h)
            self.kwargs["enroll_retry_delay"] = min(max(10, int(connect_conf.get("enroll_retry_delay", 30))), 3600)
        except (TypeError, ValueError):
            raise ImproperlyConfigured("APNS connect values must be integers")

        # we need to rate limit the notifications, to avoid DDOS.
        # → leaky bucket for the notifications
        try:
            # default leaky bucket capacity: 20 (min 1, max 1000)
            lb_capacity = min(max(1, float(workers_conf.get("capacity", 20))), 1000)
            # default leaky bucket rate: 10/s (min 0.1/s, max 1000/s)
            lb_rate = min(max(0.1, float(workers_conf.get("rate", 10))), 1000)
        except (TypeError, ValueError):
            raise ImproperlyConfigured("APNS workers capacity and rate must be floats")
        self.notification_leaky_bucket = LeakyBucket(lb_capacity, lb_rate)

        # we also need to rate limit the DB queries, to avoid querying the DB
        # in a closed short loop if no targets are acquired and the notification
        # rate limit is not used.
        # → leaky bucket for the DB queries
        # TODO hard coded capacity of 2. Verify.
        db_lb_capacity = 2
        # We calculate an estimate of the required DB query rate limit
        # based on the batch size and the notification rate limit.
        db_lb_rate = lb_rate / self.kwargs["batch_size"]
        self.db_query_leaky_bucket = LeakyBucket(db_lb_capacity, db_lb_rate)

        # APNS parameters
        # set the APNS expiration delay to the retry delay
        self.apns_expiration_seconds = self.kwargs["retry_delay"]

        # optional metrics exporter
        self.metrics_exporter = None

    def inc_counter(self, status):
        if self.metrics_exporter:
            self.metrics_exporter.inc(self.counter_name, self.target_type, status)

    def acquire_next_targets(self):
        with connection.cursor() as cursor:
            cursor.execute(self.acquire_query, self.kwargs)
            return cursor.fetchall()

    def process_target_updates(self, updates):
        logger.debug("%d target update(s) to process", len(updates))
        # release / update targets
        with connection.cursor() as cursor:
            psycopg2.extras.execute_values(
                cursor, self.update_query,
                ((pk, last_notified_at) for pk, _, _, _, last_notified_at in updates),
                template='(%s, %s::timestamp with time zone)'
            )

        # post the notification events
        for _, a_id, serial_number, udid, last_notified_at in updates:
            post_mdm_device_notification_event(
                serial_number, udid, self.apns_priority, self.apns_expiration_seconds,
                True if last_notified_at is not None else False,
                a_id if self.target_type == "user" else None,
            )

    def run_once(self):
        updates = []
        for pk, a_id, serial_number, udid, token, push_magic, topic, not_after in self.acquire_next_targets():
            client = apns_client_cache.get_or_create(topic, not_after)
            if not client:
                self.inc_counter("no_client")
                updates.append((pk, a_id, serial_number, udid, None))
            else:
                # rate limit the notifications
                self.notification_leaky_bucket.consume()
                success = client.send_notification(
                    token, push_magic,
                    priority=self.apns_priority,
                    expiration_seconds=self.apns_expiration_seconds
                )
                if success:
                    self.inc_counter("success")
                    updates.append((pk, a_id, serial_number, udid, datetime.utcnow()))
                else:
                    self.inc_counter("failure")
                    updates.append((pk, a_id, serial_number, udid, None))
        self.process_target_updates(updates)

    def run(self, metrics_exporter=None, only_once=False):
        self.metrics_exporter = metrics_exporter
        if self.metrics_exporter:
            self.metrics_exporter.start()
            self.metrics_exporter.add_counter(self.counter_name, ["target", "status"])
        exit_code = 0
        while True:
            # rate limit the DB queries
            self.db_query_leaky_bucket.consume()
            try:
                self.run_once()
            except Exception:
                logger.exception("Runtime error")
                exit_code = 1
            if exit_code or only_once:
                break
        queues.stop()
        return exit_code


class DevicesAPNSWorker(BaseAPNSWorker):
    name = "APNS worker devices"
    target_type = "device"
    acquire_query = (
        "UPDATE mdm_enrolleddevice "
        "SET notification_queued_at = NOW() "
        "FROM ("
        "  SELECT ed.id, ed.udid AS a_id, ed.serial_number, ed.udid, ed.token, ed.push_magic, pc.topic, pc.not_after "
        "  FROM mdm_enrolleddevice AS ed"
        "  JOIN mdm_pushcertificate AS pc ON (ed.push_certificate_id = pc.id)"
        "  WHERE"
        # can be notified
        "  ed.created_at < NOW() - interval '1 seconds' * %(min_target_age)s"
        "  AND ed.checkout_at IS NULL"
        "  AND ed.token IS NOT NULL"
        "  AND ed.push_magic IS NOT NULL"
        "  AND pc.certificate IS NOT NULL"
        "  AND pc.not_before < NOW()"
        "  AND pc.not_after > NOW()"
        # must be notified
        "  AND ("
        # never seen
        "    ed.last_seen_at IS NULL"
        #  seen a while ago
        "    OR ed.last_seen_at < NOW() - interval '1 seconds' * %(default_period)s"
        # has unsent command
        "    OR EXISTS ("
        "      SELECT 1 FROM mdm_devicecommand"
        "      WHERE enrolled_device_id = ed.id"
        "      AND time IS NULL AND (not_before IS NULL OR not_before < NOW())"
        "    )"
        "  )"
        # do not spam the target
        "  AND ("
        # never notified
        "    ed.last_notified_at IS NULL"
        # no pending notification
        "    OR ed.last_seen_at > ed.last_notified_at"
        # first connect not done, at least 30 seconds since last notification
        "    OR (ed.last_seen_at IS NULL AND ed.last_notified_at "
        "        < NOW() - interval '1 seconds' * %(enroll_retry_delay)s)"
        # at least 1 day since last notification
        "    OR ed.last_notified_at < NOW() - interval '1 seconds' * %(retry_delay)s"
        "  )"
        # is not currently being notified
        "  AND ("
        # not currenty being notified
        "    ed.notification_queued_at IS NULL"
        # not being notified for too long (notification worker died?)
        "    OR ed.notification_queued_at < NOW() - interval '1 seconds' * %(timeout)s"
        "  )"
        "  ORDER BY ed.last_seen_at ASC NULLS FIRST, ed.id DESC"
        "  LIMIT %(batch_size)s"
        "  FOR UPDATE OF ed SKIP LOCKED"
        ") acquired_devices "
        "WHERE mdm_enrolleddevice.id = acquired_devices.id "
        "RETURNING acquired_devices.*;"
    )
    update_query = (
        "UPDATE mdm_enrolleddevice SET "
        "notification_queued_at = NULL,"
        "last_notified_at = CASE "
        "WHEN updates.last_notified_at IS NULL THEN mdm_enrolleddevice.last_notified_at "
        "ELSE updates.last_notified_at "
        "END "
        "FROM (values %s) AS updates(pk, last_notified_at) "
        "WHERE mdm_enrolleddevice.id = updates.pk;"
    )


class UsersAPNSWorker(BaseAPNSWorker):
    name = "APNS worker users"
    target_type = "user"
    acquire_query = (
        "UPDATE mdm_enrolleduser "
        "SET notification_queued_at = NOW() "
        "FROM ("
        "  SELECT eu.id, eu.user_id AS a_id,"
        "  ed.serial_number, ed.udid, eu.token, ed.push_magic, pc.topic, pc.not_after "
        "  FROM mdm_enrolleduser AS eu"
        "  JOIN mdm_enrolleddevice AS ed ON (eu.enrolled_device_id = ed.id)"
        "  JOIN mdm_pushcertificate AS pc ON (ed.push_certificate_id = pc.id)"
        "  WHERE"
        # can be notified
        "  eu.created_at < NOW() - interval '1 seconds' * %(min_target_age)s"
        "  AND ed.checkout_at IS NULL"
        "  AND eu.token IS NOT NULL"
        "  AND ed.push_magic IS NOT NULL"
        "  AND pc.certificate IS NOT NULL"
        "  AND pc.not_before < NOW()"
        "  AND pc.not_after > NOW()"
        # must be notified
        "  AND ("
        # never seen
        "    eu.last_seen_at IS NULL"
        #  seen a while ago
        "    OR eu.last_seen_at < NOW() - interval '1 seconds' * %(default_period)s"
        # has unsent command
        "    OR EXISTS ("
        "      SELECT 1 FROM mdm_usercommand"
        "      WHERE enrolled_user_id = eu.id"
        "      AND time IS NULL AND (not_before IS NULL OR not_before < NOW())"
        "    )"
        "  )"
        # do not spam the target
        "  AND ("
        # never notified
        "    eu.last_notified_at IS NULL"
        # no pending notification
        "    OR eu.last_seen_at > eu.last_notified_at"
        # first connect not done, at least 30 seconds since last notification
        "    OR (eu.last_seen_at IS NULL AND eu.last_notified_at "
        "        < NOW() - interval '1 seconds' * %(enroll_retry_delay)s)"
        # at least 1 day since last notification
        "    OR eu.last_notified_at < NOW() - interval '1 seconds' * %(retry_delay)s"
        "  )"
        # is not currently being notified
        "  AND ("
        # not currenty being notified
        "    eu.notification_queued_at IS NULL"
        # not being notified for too long (notification worker died?)
        "    OR eu.notification_queued_at < NOW() - interval '1 seconds' * %(timeout)s"
        "  )"
        "  ORDER BY eu.last_seen_at ASC NULLS FIRST, eu.id DESC"
        "  LIMIT %(batch_size)s"
        "  FOR UPDATE OF eu SKIP LOCKED"
        ") acquired_users "
        "WHERE mdm_enrolleduser.id = acquired_users.id "
        "RETURNING acquired_users.*;"
    )
    update_query = (
        "UPDATE mdm_enrolleduser SET "
        "notification_queued_at = NULL,"
        "last_notified_at = CASE "
        "WHEN updates.last_notified_at IS NULL THEN mdm_enrolleduser.last_notified_at "
        "ELSE updates.last_notified_at "
        "END "
        "FROM (values %s) AS updates(pk, last_notified_at) "
        "WHERE mdm_enrolleduser.id = updates.pk;"
    )


def get_workers():
    yield DevicesAPNSWorker()
    yield UsersAPNSWorker()
