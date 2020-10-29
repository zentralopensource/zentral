from importlib import import_module
import logging
import time
from django.utils.text import slugify
from kombu.utils import json
from google.api_core.exceptions import AlreadyExists
from google.cloud import pubsub_v1
from google.oauth2 import service_account
from zentral.conf import settings


logger = logging.getLogger('zentral.core.queues.backends.google_pubsub')


class BaseWorker:
    name = "UNDEFINED"
    counters = []

    def setup_metrics_exporter(self, *args, **kwargs):
        self.metrics_exporter = kwargs.pop("metrics_exporter", None)
        if self.metrics_exporter:
            for name, label in self.counters:
                self.metrics_exporter.add_counter(name, [label])
            self.metrics_exporter.start()

    def inc_counter(self, name, label):
        if self.metrics_exporter:
            self.metrics_exporter.inc(name, label)

    def log(self, msg, level, *args):
        logger.log(level, "{} - {}".format(self.name, msg), *args)

    def log_debug(self, msg, *args):
        self.log(msg, logging.DEBUG, *args)

    def log_info(self, msg, *args):
        self.log(msg, logging.INFO, *args)

    def log_error(self, msg, *args):
        self.log(msg, logging.ERROR, *args)


class PreprocessWorker(BaseWorker):
    name = "preprocess worker"
    counters = (
        ("preprocessed_events", "routing_key"),
        ("produced_events", "event_type"),
    )

    def __init__(self, raw_events_topic, events_topic, credentials):
        self.raw_events_topic = raw_events_topic
        self.events_topic = events_topic
        self.credentials = credentials
        # preprocessors
        self.preprocessors = {
            preprocessor.routing_key: preprocessor
            for preprocessor in self._get_preprocessors()
        }

    def _get_preprocessors(self):
        for app in settings['apps']:
            try:
                preprocessors_module = import_module("{}.preprocessors".format(app))
            except ImportError:
                pass
            else:
                yield from getattr(preprocessors_module, "get_preprocessors")()

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)

        # subscriber client
        self.log_info("initialize subscriber")
        subscriber_client = pubsub_v1.SubscriberClient(credentials=self.credentials)
        project_id = self.raw_events_topic.split("/")[1]
        sub_path = subscriber_client.subscription_path(project_id, "raw-events-subscription")

        # create subscription
        try:
            subscriber_client.create_subscription(sub_path, self.raw_events_topic)
        except AlreadyExists:
            self.log_info("preprocess worker subscription %s already exists", sub_path)
        else:
            self.log_info("preprocess worker subscription %s created", sub_path)

        # publisher client
        self.log_info("initialize publisher")
        self.publisher_client = pubsub_v1.PublisherClient(credentials=self.credentials)

        # async pull
        self.log_info("start async pull")
        pull_future = subscriber_client.subscribe(sub_path, self.callback)
        with subscriber_client:
            try:
                pull_future.result()
            except Exception:
                pull_future.cancel()

    def callback(self, message):
        routing_key = message.attributes.get("routing_key")
        if not routing_key:
            self.log_error("Message w/o routing key")
        else:
            preprocessor = self.preprocessors.get(routing_key)
            if not preprocessor:
                self.log_error("No preprocessor for routing key %s", routing_key)
            else:
                for event in preprocessor.process_raw_event(json.loads(message.data)):
                    new_message = json.dumps(event.serialize(machine_metadata=False)).encode("utf-8")
                    self.publisher_client.publish(self.events_topic, new_message)
                    self.inc_counter("produced_events", event.event_type)
        message.ack()
        self.inc_counter("preprocessed_events", routing_key or "UNKNOWN")


class EnrichWorker(BaseWorker):
    name = "enrich worker"
    counters = (
        ("enriched_events", "event_type"),
        ("produced_events", "event_type"),
    )

    def __init__(self, events_topic, enriched_events_topic, credentials, enrich_event):
        self.events_topic = events_topic
        self.enriched_events_topic = enriched_events_topic
        self.credentials = credentials
        self.enrich_event = enrich_event

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)

        # subscriber client
        self.log_info("initialize subscriber")
        subscriber_client = pubsub_v1.SubscriberClient(credentials=self.credentials)
        project_id = self.events_topic.split("/")[1]
        sub_path = subscriber_client.subscription_path(project_id, "events-subscription")

        # create subscription
        try:
            subscriber_client.create_subscription(sub_path, self.events_topic)
        except AlreadyExists:
            self.log_info("enrich worker subscription %s already exists", sub_path)
        else:
            self.log_info("enrich worker subscription %s created", sub_path)

        # publisher client
        self.log_info("initialize publisher")
        self.publisher_client = pubsub_v1.PublisherClient(credentials=self.credentials)

        # async pull
        self.log_info("start async pull")
        pull_future = subscriber_client.subscribe(sub_path, self.callback)
        with subscriber_client:
            try:
                pull_future.result()
            except Exception:
                pull_future.cancel()

    def callback(self, message):
        event_dict = json.loads(message.data)
        try:
            for event in self.enrich_event(event_dict):
                new_message = json.dumps(event.serialize(machine_metadata=False)).encode("utf-8")
                self.publisher_client.publish(self.enriched_events_topic, new_message)
                self.inc_counter("produced_events", event.event_type)
        except Exception as exception:
            logger.exception("Requeuing message with 1s delay: %s", exception)
            time.sleep(1)
            message.nack()
        else:
            message.ack()
            self.inc_counter("enriched_events", event_dict['_zentral']['type'])


class ProcessWorker(BaseWorker):
    name = "process worker"
    counters = (
        ("processed_events", "event_type"),
    )

    def __init__(self, enriched_events_topic, credentials, process_event):
        self.enriched_events_topic = enriched_events_topic
        self.credentials = credentials
        self.process_event = process_event

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)

        # subscriber client
        self.log_info("initialize subscriber")
        subscriber_client = pubsub_v1.SubscriberClient(credentials=self.credentials)
        project_id = self.enriched_events_topic.split("/")[1]
        sub_path = subscriber_client.subscription_path(project_id, "process-enriched-events-subscription")

        # create subscription
        try:
            subscriber_client.create_subscription(sub_path, self.enriched_events_topic)
        except AlreadyExists:
            self.log_info("process worker subscription %s already exists", sub_path)
        else:
            self.log_info("process worker subscription %s created", sub_path)

        # async pull
        self.log_info("start async pull")
        pull_future = subscriber_client.subscribe(sub_path, self.callback)
        with subscriber_client:
            try:
                pull_future.result()
            except Exception:
                pull_future.cancel()

    def callback(self, message):
        event_dict = json.loads(message.data)
        self.process_event(event_dict)
        message.ack()
        self.inc_counter("processed_events", event_dict['_zentral']['type'])


class StoreWorker(BaseWorker):
    counters = (
        ("stored_events", "event_type"),
    )

    def __init__(self, enriched_events_topic, credentials, event_store):
        self.enriched_events_topic = enriched_events_topic
        self.credentials = credentials
        self.event_store = event_store
        self.name = "store worker {}".format(self.event_store.name)

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)

        # subscriber client
        self.log_info("initialize subscriber")
        subscriber_client = pubsub_v1.SubscriberClient(credentials=self.credentials)
        project_id = self.enriched_events_topic.split("/")[1]
        sub_path = subscriber_client.subscription_path(
            project_id,
            "{}-store-enriched-events-subscription".format(slugify(self.event_store.name))
        )

        # create subscription
        try:
            subscriber_client.create_subscription(sub_path, self.enriched_events_topic)
        except AlreadyExists:
            self.log_info("store worker subscription %s already exists", sub_path)
        else:
            self.log_info("store worker subscription %s created", sub_path)

        # prometheus
        prometheus_port = kwargs.pop("prometheus_port", None)
        if prometheus_port:
            self.log_info("start prometheus server on port %s", prometheus_port)
            self.start_prometheus_server(prometheus_port)

        # async pull
        self.log_info("start async pull")
        pull_future = subscriber_client.subscribe(sub_path, self.callback)
        with subscriber_client:
            try:
                pull_future.result()
            except Exception:
                pull_future.cancel()

    def callback(self, message):
        self.log_debug("store event")
        event_dict = json.loads(message.data)
        try:
            self.event_store.store(event_dict)
        except Exception:
            logger.exception("Could add event to store %s", self.event_store.name)
            message.nack()
        else:
            message.ack()
            self.inc_counter("stored_events", event_dict['_zentral']['type'])


class EventQueues(object):
    def __init__(self, config_d):
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

    def _publish(self, topic, event_dict, **kwargs):
        message = json.dumps(event_dict).encode("utf-8")
        if self.publisher_client is None:
            self.publisher_client = pubsub_v1.PublisherClient(credentials=self.credentials)
        self.publisher_client.publish(topic, message, **kwargs)

    def get_preprocess_worker(self):
        return PreprocessWorker(self.raw_events_topic, self.events_topic, self.credentials)

    def get_enrich_worker(self, enrich_event):
        return EnrichWorker(self.events_topic, self.enriched_events_topic, self.credentials, enrich_event)

    def get_process_worker(self, process_event):
        return ProcessWorker(self.enriched_events_topic, self.credentials, process_event)

    def get_store_worker(self, event_store):
        return StoreWorker(self.enriched_events_topic, self.credentials, event_store)

    def post_raw_event(self, routing_key, raw_event):
        self._publish(self.raw_events_topic, raw_event, routing_key=routing_key)

    def post_event(self, event):
        self._publish(self.events_topic, event.serialize(machine_metadata=False))
