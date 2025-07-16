from collections import deque
from importlib import import_module
import logging
import queue
import random
import threading
import time
from django.utils.functional import cached_property
from kombu.utils import json
from google.cloud import pubsub_v1
from google.oauth2 import service_account
from zentral.conf import settings
from zentral.core.queues.backends.base import BaseEventQueues
from zentral.core.queues.exceptions import RetryLater
from .consumer import BaseWorker, Consumer, ConsumerProducer


logger = logging.getLogger('zentral.core.queues.backends.google_pubsub')


class PreprocessWorker(ConsumerProducer):
    name = "preprocess worker"
    subscription_id = "raw-events-subscription"
    counters = (
        ("preprocessed_events", "routing_key"),
        ("produced_events", "event_type"),
    )

    @cached_property
    def preprocessors(self):
        preprocessors = {}
        for app in settings['apps']:
            try:
                preprocessors_module = import_module("{}.preprocessors".format(app))
            except ImportError:
                pass
            else:
                for preprocessor in getattr(preprocessors_module, "get_preprocessors")():
                    preprocessors[preprocessor.routing_key] = preprocessor
        return preprocessors

    def callback(self, message):
        routing_key = message.attributes.get("routing_key")
        if not routing_key:
            self.log_error("Message w/o routing key")
        else:
            preprocessor = self.preprocessors.get(routing_key)
            if not preprocessor:
                self.log_error("No preprocessor for routing key %s", routing_key)
            else:
                try:
                    for event in preprocessor.process_raw_event(json.loads(message.data)):
                        self.publish_event(event, machine_metadata=False)
                        self.inc_counter("produced_events", event.event_type)
                except RetryLater:
                    self.log_error("Message with routing key %s could not be preprocessed. Re-enqueued", routing_key)
                    message.nack()
                    return
        message.ack()
        self.inc_counter("preprocessed_events", routing_key or "UNKNOWN")


class EnrichWorker(ConsumerProducer):
    name = "enrich worker"
    subscription_id = "events-subscription"
    counters = (
        ("enriched_events", "event_type"),
        ("produced_events", "event_type"),
    )

    def __init__(self, events_topic, enriched_events_topic, credentials, enrich_event):
        super().__init__(events_topic, enriched_events_topic, credentials)
        self.enrich_event = enrich_event

    def callback(self, message):
        event_dict = json.loads(message.data)
        event_type = event_dict['_zentral']['type']
        try:
            for event in self.enrich_event(event_dict):
                self.publish_event(event, machine_metadata=True)
                self.inc_counter("produced_events", event.event_type)
        except Exception:
            self.log_exception("Exception. NACK and shutdown")
            message.nack()
            self.shutdown(error=True)
        else:
            message.ack()
            self.inc_counter("enriched_events", event_type)


class ProcessWorker(Consumer):
    name = "process worker"
    subscription_id = "process-enriched-events-subscription"
    counters = (
        ("processed_events", "event_type"),
    )

    def __init__(self, enriched_events_topic, credentials, process_event):
        super().__init__(enriched_events_topic, credentials)
        self.process_event = process_event

    def callback(self, message):
        event_dict = json.loads(message.data)
        event_type = event_dict['_zentral']['type']
        self.process_event(event_dict)
        message.ack()
        self.inc_counter("processed_events", event_type)


class StoreWorker(Consumer):
    counters = (
        ("skipped_events", "event_type"),
        ("stored_events", "event_type"),
    )

    def __init__(self, enriched_events_topic, credentials, event_store):
        self.name = f"store worker {event_store.name}"
        self.subscription_id = f"{event_store.slug}-store-enriched-events-subscription"
        super().__init__(enriched_events_topic, credentials)
        self.event_store = event_store

    def callback(self, message):
        self.log_debug("store event")
        event_dict = json.loads(message.data)
        event_type = event_dict['_zentral']['type']
        if not self.event_store.is_serialized_event_included(event_dict):
            self.log_debug("skip %s event", event_type)
            message.ack()
            self.inc_counter("skipped_events", event_type)
            return
        try:
            self.event_store.store(event_dict)
        except Exception:
            self.log_exception("Exception. NACK and shutdown")
            message.nack()
            self.shutdown(error=True)
        else:
            message.ack()
            self.inc_counter("stored_events", event_type)


class BulkStoreWorkerReceiveThread(threading.Thread):
    def __init__(self, thread_id, client, sub_path, stop_event, out_queue, max_messages):
        logger.debug("build receive thread on subscription %s", sub_path)
        self.client = client
        self.sub_path = sub_path
        self.stop_event = stop_event
        self.out_queue = out_queue
        self.max_messages = max_messages
        super().__init__(name=f"Pub/Sub receive thread {thread_id}")

    def run(self):
        logger.info("[%s] start on subscription %s", self.name, self.sub_path)
        while not self.stop_event.is_set():
            try:
                response = self.client.pull(
                    request={"subscription": self.sub_path, "max_messages": self.max_messages},
                )
            except Exception:
                logger.exception("[%s] could not receive events", self.name)
                seconds = random.uniform(10, 60)
                logger.error("[%s] retry in %.1fs", self.name, seconds)
                slices = 50
                for i in range(slices):
                    time.sleep(seconds / slices)
                    if self.stop_event.is_set():
                        logger.info("[%s] graceful exit", self.name)
                        break
            else:
                i = 0
                for received_message in response.received_messages:
                    if self.stop_event.is_set():
                        break
                    i += 1
                    ack_id = received_message.ack_id
                    event_d = json.loads(received_message.message.data)
                    while True:
                        try:
                            self.out_queue.put((ack_id, event_d), timeout=1)
                        except queue.Full:
                            if self.stop_event.is_set():
                                break
                        else:
                            break
                logger.debug("[%s] %d event(s) received and queued", self.name, i)


class BulkStoreWorkerAckThread(threading.Thread):
    max_ack_id_age_seconds = 5

    def __init__(self, client, sub_path, stop_event, in_queue, max_ack_ids):
        logger.debug("build ack thread on subscription %s", sub_path)
        self.client = client
        self.sub_path = sub_path
        self.stop_event = stop_event
        self.in_queue = in_queue
        self.max_ack_ids = max_ack_ids
        super().__init__(name="Pub/Sub ack thread")

    def run(self):
        logger.info("[%s] start on subscription %s", self.name, self.sub_path)
        self.ack_ids = []
        self.min_ack_id_ts = None
        while True:
            try:
                ack_id, ack_id_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new message to acknowledge", self.name)
                if self.ack_ids:
                    if self.stop_event.is_set():
                        logger.debug("[%s] ack messages before graceful exit", self.name)
                        self.acknowledge()
                    else:
                        if time.monotonic() > self.min_ack_id_ts + self.max_ack_id_age_seconds:
                            logger.debug("[%s] ack messages because max age reached", self.name)
                            self.acknowledge()
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                logger.debug("[%s] ack id %s: new message to acknowledge %s",
                             self.name, ack_id, ack_id_ts)
                self.ack_ids.append(ack_id)
                self.min_ack_id_ts = min(ack_id_ts, self.min_ack_id_ts or ack_id_ts)
                if len(self.ack_ids) >= self.max_ack_ids:
                    self.acknowledge()

    def acknowledge(self):
        logger.debug("[%s] acknowledge %s message(s)", self.name, len(self.ack_ids))
        try:
            self.client.acknowledge(
                request={"subscription": self.sub_path, "ack_ids": self.ack_ids}
            )
        except Exception:
            logger.exception("[%s] could not acknowledge message(s)", self.name)
        else:
            logger.debug("[%s] %d message(s) acknowledged", self.name, len(self.ack_ids))
        self.ack_ids = []
        self.min_ack_id_ts = None


class BulkStoreWorker(BaseWorker):
    ack_deadline_seconds = 60  # increased from the default 10s. TODO verify.
    counters = (
        ("skipped_events", "event_type"),
        ("stored_events", "event_type"),
    )
    max_event_age_seconds = 5
    receive_thread_count = 2  # TODO verify

    def __init__(self, enriched_events_topic, credentials, event_store):
        self.name = f"store worker {event_store.name}"
        self.subscription_id = f"{event_store.slug}-store-enriched-events-subscription"
        super().__init__(enriched_events_topic, credentials)
        self.event_store = event_store
        # threading
        self.process_message_queue = queue.Queue(maxsize=self.event_store.batch_size)
        self.ack_message_queue = queue.Queue(maxsize=self.event_store.batch_size)
        self.stop_receiving_event = threading.Event()
        self.stop_event = threading.Event()
        # batch
        self.batch = deque()
        self.batch_start_ts = None

    def _skip_event(self, event_d):
        event_type = event_d['_zentral']['type']
        if not self.event_store.is_serialized_event_included(event_d):
            self.inc_counter("skipped_events", event_type)
            return True
        else:
            return False

    def _process_batch(self):
        batch_size = len(self.batch)
        self.log_debug("store %d events", batch_size)
        event_info = {}

        def iter_events():
            while self.batch:
                ack_id, event_d = self.batch.popleft()
                event_metadata = event_d['_zentral']
                event_key = (event_metadata["id"], event_metadata["index"])
                event_type = event_metadata['type']
                event_info[event_key] = (ack_id, event_type)
                yield event_d

        stored_event_count = 0
        for stored_event_key in self.event_store.bulk_store(iter_events()):
            try:
                ack_id, event_type = event_info[stored_event_key]
            except KeyError:
                self.log_error("unknown stored event %s", stored_event_key)
            else:
                self.ack_message_queue.put((ack_id, time.monotonic()))
                self.inc_counter("stored_events", event_type)
                stored_event_count += 1
        self.batch_start_ts = None

        if stored_event_count < batch_size:
            self.log_error("only %s/%s event(s) stored", stored_event_count, batch_size)
        else:
            self.log_debug("%s/%s events stored", stored_event_count, batch_size)

    def _start_run_loop(self):
        while True:
            try:
                ack_id, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                self.log_debug("no new event to process")
                if self.batch:
                    if self.stop_receiving_event.is_set():
                        self.log_debug("process events before graceful exit")
                        self._process_batch()
                    elif time.monotonic() > self.batch_start_ts + self.max_event_age_seconds:
                        self.log_debug("process events because max event age reached")
                        self._process_batch()
                if self.stop_receiving_event.is_set():
                    break
            else:
                if self._skip_event(event_d):
                    self.log_debug("ack id %s: event skipped", ack_id)
                    self.ack_message_queue.put((ack_id, time.monotonic()))
                    if self.batch and time.monotonic() > self.batch_start_ts + self.max_event_age_seconds:
                        self.log_debug("process events because max event age reached")
                        self._process_batch()
                else:
                    self.log_debug("ack id %s: queue new event for batch processing", ack_id)
                    self.batch.append((ack_id, event_d))
                    if self.batch_start_ts is None:
                        self.batch_start_ts = time.monotonic()
                    if len(self.batch) >= self.event_store.batch_size:
                        self.log_debug("process events because max batch size reached")
                        self._process_batch()

    def do_handle_signal(self):
        if not self.stop_receiving_event.is_set():
            self.log_info("stop receiving events")
            self.stop_receiving_event.set()

    def do_run(self):
        # threads
        threads = [
            BulkStoreWorkerAckThread(
                self.subscriber_client, self.subscription_path,
                self.stop_event,
                self.ack_message_queue,
                self.event_store.batch_size
            )
        ]
        for thread_id in range(self.receive_thread_count):
            threads.append(
                BulkStoreWorkerReceiveThread(
                    thread_id + 1,
                    self.subscriber_client, self.subscription_path,
                    self.stop_receiving_event,
                    self.process_message_queue,
                    self.event_store.batch_size
                )
            )
        for thread in threads:
            thread.start()

        try:
            self._start_run_loop()
        except Exception as e:
            self.exit_code = 1
            self.log_error("run loop exception: %s", e)
            if not self.stop_receiving_event.is_set():
                self.log_info("stop receiving")
                self.stop_receiving_event.set()

        # graceful stop
        if not self.stop_event.is_set():
            self.log_info("set stop event")
            self.stop_event.set()
            for thread in threads:
                thread.join()
            self.log_info("all threads stopped")
        self.subscriber_client.close()


class EventQueues(BaseEventQueues):
    def __init__(self, config_d):
        super().__init__(config_d)
        # topics
        topics = config_d["topics"]
        self.raw_events_topic = topics["raw_events"]
        self.events_topic = topics["events"]
        self.enriched_events_topic = topics["enriched_events"]

        # credentials
        self.credentials = None
        credentials_file = config_d.get("credentials")
        if credentials_file:
            credentials = service_account.Credentials.from_service_account_file(credentials_file)
            self.credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])

        # publisher client
        self.publisher_client = None

    def _publish(self, topic, event_dict, **attributes):
        message = json.dumps(event_dict).encode("utf-8")
        if self.publisher_client is None:
            self.publisher_client = pubsub_v1.PublisherClient(credentials=self.credentials)
        self.publisher_client.publish(topic, message, **attributes)

    def get_preprocess_worker(self):
        return PreprocessWorker(self.raw_events_topic, self.events_topic, self.credentials)

    def get_enrich_worker(self, enrich_event):
        return EnrichWorker(self.events_topic, self.enriched_events_topic, self.credentials, enrich_event)

    def get_process_worker(self, process_event):
        return ProcessWorker(self.enriched_events_topic, self.credentials, process_event)

    def get_store_worker(self, event_store):
        if event_store.batch_size > 1:
            worker_class = BulkStoreWorker
        else:
            worker_class = StoreWorker
        return worker_class(self.enriched_events_topic, self.credentials, event_store)

    def post_raw_event(self, routing_key, raw_event):
        self._publish(self.raw_events_topic, raw_event, routing_key=routing_key)

    def post_event(self, event):
        self._publish(self.events_topic, event.serialize(machine_metadata=False), event_type=event.event_type)
