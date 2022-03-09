from datetime import datetime
import logging
from django.db import transaction
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_yield_events
from zentral.contrib.wsone.api_client import Client, TooManyRequestsError
from zentral.contrib.wsone.models import Instance
from zentral.core.events import event_cls_from_type
from zentral.core.queues.exceptions import RetryLater


logger = logging.getLogger("zentral.contrib.wsone.preprocessors.webhook")


class WebhookEventPreprocessor(object):
    routing_key = "wsone_events"

    def __init__(self):
        self.clients = {}

    def _get_client(self, instance_d):
        client = None
        instance_pk = instance_d["pk"]
        instance_version = instance_d["version"]
        try:
            client, client_instance_version = self.clients[instance_pk]
        except KeyError:
            pass
        else:
            if client_instance_version < instance_version:
                client = None
        if client is None:
            try:
                instance = Instance.objects.get(pk=instance_pk)
            except Instance.DoesNotExist:
                logger.error("Instance %s not found", instance_pk)
                return
            client = Client.from_instance(instance)
            self.clients[instance_pk] = (client, instance.version)
        return client

    def _update_machine(self, client, device_id):
        logger.info("Update machine %s %s", client.host, device_id)
        try:
            ms_tree = client.get_machine_snapshot_tree(device_id)
        except TooManyRequestsError:
            raise RetryLater
        if not ms_tree:
            logger.error("Could not get machine %s %s snapshot tree", client.host, device_id)
            return
        with transaction.atomic():
            yield from commit_machine_snapshot_and_yield_events(ms_tree)

    def process_raw_event(self, raw_event):
        instance_d = raw_event["wsone_instance"]
        client = self._get_client(instance_d)
        if client is None:
            return

        # event from an excluded group?
        wsone_event = raw_event["wsone_event"]
        try:
            if client.is_excluded_event(wsone_event):
                return
        except TooManyRequestsError:
            raise RetryLater

        # update device if possible
        device_id = wsone_event.pop("DeviceId", None)
        if device_id:
            yield from self._update_machine(client, device_id)
        else:
            logger.warning("Workspace ONE event without DeviceId")

        # yield wsone event
        serial_number = wsone_event.pop("SerialNumber")
        if not serial_number:
            logger.error("Workspace ONE event without SerialNumber")
            return

        wsone_event_type = wsone_event.pop("EventType", None)
        if not wsone_event_type:
            logger.error("Workspace ONE event without EventType")
            return

        event_type = None
        payload = {k: v for k, v in wsone_event.items() if v}
        if wsone_event_type == "Break MDM Confirmed":
            event_type = "wsone_break_mdm_confirmed"
        elif wsone_event_type == "Compliance Status Changed":
            event_type = "wsone_compliance_status_changed"
        elif wsone_event_type == "Compromised Status Changed":
            event_type = "wsone_compromised_status_changed"
        elif wsone_event_type == "Device MCC":
            event_type = "wsone_mcc_changed"
        elif wsone_event_type == "Device Operating System Changed":
            event_type = "wsone_os_changed"
        elif wsone_event_type == "Device Organization Group Changed":
            event_type = "wsone_organization_group_changed"
        elif wsone_event_type == "Enrollment Complete":
            event_type = "wsone_enrollment_complete"
        elif wsone_event_type == "MDM Enrollment Complete":
            event_type = "wsone_mdm_enrollment_complete"
        else:
            logger.warning("Unknown Workspace ONE event type: %s", wsone_event_type)
            return

        def get_created_at(payload):
            event_time = payload.get("EventTime")
            if not event_time:
                logger.error("EventTime not found or empty in %s event", event_type)
                return
            for ts_length in (26, 23):
                # Workspace ONE has sometimes 5 or 7 decimal places for the microseconds
                try:
                    return datetime.fromisoformat(event_time[:ts_length])
                except Exception:
                    pass
            else:
                logger.error("Could not parse event time '%s' in %s event", event_time, event_type)

        event_cls = event_cls_from_type(event_type)
        yield from event_cls.build_from_machine_request_payloads(
            serial_number,
            raw_event["request"]["user_agent"],
            raw_event["request"]["ip"],
            [payload],
            get_created_at=get_created_at,
            observer=raw_event["observer"]
        )
