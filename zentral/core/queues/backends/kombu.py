from importlib import import_module
import logging
import time
from zentral.conf import settings
from kombu import Connection, Consumer, Exchange, Queue
from kombu.mixins import ConsumerMixin, ConsumerProducerMixin
from kombu.pools import producers
from zentral.utils.json import save_dead_letter


logger = logging.getLogger('zentral.core.queues.backends.kombu')


raw_events_exchange = Exchange('raw_events', type='direct', durable=True)

events_exchange = Exchange('events', type="fanout", durable=True)
enrich_events_queue = Queue('enrich_events',
                            exchange=events_exchange,
                            durable=True)
enriched_events_exchange = Exchange('enriched_events', type="fanout", durable=True)
process_events_queue = Queue('process_events',
                             exchange=enriched_events_exchange,
                             durable=True)


class BaseWorker:
    name = "UNDEFINED"
    counters = []

    def setup_metrics_exporter(self, *args, **kwargs):
        self.log_info("run")
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


class PreprocessWorker(ConsumerProducerMixin, BaseWorker):
    name = "preprocess worker"
    counters = (
        ("preprocessed_events", "routing_key"),
        ("produced_events", "event_type"),
    )

    def __init__(self, connection):
        self.connection = connection
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
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        queues = [
            Queue(preprocessor.routing_key, exchange=raw_events_exchange,
                  routing_key=preprocessor.routing_key, durable=True)
            for routing_key, preprocessor in self.preprocessors.items()
        ]
        return [Consumer(default_channel,
                         queues=queues,
                         accept=['json'],
                         callbacks=[self.do_preprocess_raw_event])]

    def do_preprocess_raw_event(self, body, message):
        routing_key = message.delivery_info.get("routing_key")
        if not routing_key:
            logger.error("Message w/o routing key")
        else:
            preprocessor = self.preprocessors.get(routing_key)
            if not preprocessor:
                logger.error("No preprocessor for routing key %s", routing_key)
            else:
                for event in preprocessor.process_raw_event(body):
                    self.producer.publish(event.serialize(machine_metadata=False),
                                          serializer='json',
                                          exchange=events_exchange,
                                          declare=[events_exchange])
                    self.inc_counter("produced_events", event.event_type)
        message.ack()
        self.inc_counter("preprocessed_events", routing_key or "UNKNOWN")


class EnrichWorker(ConsumerProducerMixin, BaseWorker):
    name = "enrich worker"
    counters = (
        ("enriched_events", "event_type"),
        ("produced_events", "event_type"),
    )

    def __init__(self, connection, enrich_event):
        self.connection = connection
        self.enrich_event = enrich_event
        self.name = "enrich worker"

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[enrich_events_queue],
                         accept=['json'],
                         callbacks=[self.do_enrich_event])]

    def do_enrich_event(self, body, message):
        self.log_debug("enrich event")
        try:
            for event in self.enrich_event(body):
                self.producer.publish(event.serialize(machine_metadata=False),
                                      serializer='json',
                                      exchange=enriched_events_exchange,
                                      declare=[enriched_events_exchange])
                self.inc_counter("produced_events", event.event_type)
        except Exception as exception:
            logger.exception("Requeuing message with 1s delay: %s", exception)
            time.sleep(1)
            message.requeue()
        else:
            message.ack()
            self.inc_counter("enriched_events", event.event_type)


class ProcessWorker(ConsumerMixin, BaseWorker):
    name = "process worker"
    counters = (
        ("processed_events", "event_type"),
    )

    def __init__(self, connection, process_event):
        self.connection = connection
        self.process_event = process_event

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[process_events_queue],
                         accept=['json'],
                         callbacks=[self.do_process_event])]

    def do_process_event(self, body, message):
        self.log_debug("process event")
        event_type = body['_zentral']['type']
        self.process_event(body)
        message.ack()
        self.inc_counter("processed_events", event_type)


class StoreWorker(ConsumerMixin, BaseWorker):
    counters = (
        ("stored_events", "event_type"),
    )

    def __init__(self, connection, event_store):
        self.connection = connection
        self.event_store = event_store
        self.name = "store worker {}".format(self.event_store.name)
        self.input_queue = Queue(('store_events_{}'.format(self.event_store.name)).replace(" ", "_"),
                                 exchange=enriched_events_exchange,
                                 durable=True)

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().setup_metrics_exporter(*args, **kwargs)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[self.input_queue],
                         accept=['json'],
                         callbacks=[self.do_store_event])]

    def do_store_event(self, body, message):
        self.log_debug("store event")
        event_type = body['_zentral']['type']
        try:
            self.event_store.store(body)
        except Exception:
            logger.exception("Could add event to store %s", self.event_store.name)
            save_dead_letter(body, "event store {} error".format(self.event_store.name))
            message.reject()
        else:
            message.ack()
            self.inc_counter("stored_events", event_type)


class EventQueues(object):
    def __init__(self, config_d):
        self.backend_url = config_d['backend_url']
        self.transport_options = config_d.get('transport_options')
        self.connection = self._get_connection()

    def _get_connection(self):
        return Connection(self.backend_url, transport_options=self.transport_options)

    def get_preprocess_worker(self):
        return PreprocessWorker(self._get_connection())

    def get_enrich_worker(self, enrich_event):
        return EnrichWorker(self._get_connection(), enrich_event)

    def get_process_worker(self, process_event):
        return ProcessWorker(self._get_connection(), process_event)

    def get_store_worker(self, event_store):
        return StoreWorker(self._get_connection(), event_store)

    def post_raw_event(self, routing_key, raw_event):
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(raw_event,
                             serializer='json',
                             exchange=raw_events_exchange,
                             routing_key=routing_key,
                             declare=[raw_events_exchange])

    def post_event(self, event):
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(event.serialize(machine_metadata=False),
                             serializer='json',
                             exchange=events_exchange,
                             declare=[events_exchange])
