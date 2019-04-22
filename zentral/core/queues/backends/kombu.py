import logging
import time
from kombu import Connection, Consumer, Exchange, Queue
from kombu.mixins import ConsumerMixin, ConsumerProducerMixin
from kombu.pools import producers
from prometheus_client import Counter
from zentral.utils.prometheus import PrometheusWorkerMixin


logger = logging.getLogger('zentral.core.queues.backends.kombu')


events_exchange = Exchange('events', type="fanout", durable=True)
enrich_events_queue = Queue('enrich_events',
                            exchange=events_exchange,
                            durable=True)
enriched_events_exchange = Exchange('enriched_events', type="fanout", durable=True)
process_events_queue = Queue('process_events',
                             exchange=enriched_events_exchange,
                             durable=True)


class LoggingMixin(object):
    def log(self, msg, level):
        logger.log(level, "{} - {}".format(self.name, msg))

    def log_info(self, msg):
        self.log(msg, logging.INFO)

    def log_debug(self, msg):
        self.log(msg, logging.DEBUG)


class PreprocessWorker(ConsumerProducerMixin, LoggingMixin, PrometheusWorkerMixin):
    def __init__(self, connection, event_preprocessor):
        self.connection = connection
        self.event_preprocessor = event_preprocessor
        input_exchange = Exchange(event_preprocessor.input_queue_name, type="fanout", durable=True)
        self.input_queue = Queue(event_preprocessor.input_queue_name, exchange=input_exchange, durable=True)
        self.name = self.event_preprocessor.name

    def setup_prometheus_metrics(self):
        self.preprocessed_events_counter = Counter(
            "preprocessed_events",
            "Preprocessed events"
        )
        self.produced_events_counter = Counter(
            "produced_events",
            "Produced events",
            ["event_type"]
        )

    def run(self, *args, **kwargs):
        self.log_info("run")
        prometheus_port = kwargs.pop("prometheus_port")
        if prometheus_port:
            self.start_prometheus_server(prometheus_port)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[self.input_queue],
                         accept=['json'],
                         callbacks=[self.do_preprocess_raw_event])]

    def do_preprocess_raw_event(self, body, message):
        self.log_debug("process raw event")
        try:
            for event in self.event_preprocessor.process_raw_event(body):
                self.produced_events_counter.labels(event.event_type).inc()
                self.producer.publish(event.serialize(machine_metadata=False),
                                      serializer='json',
                                      exchange=events_exchange,
                                      declare=[events_exchange])
        except Exception as exception:
            logger.exception("Requeuing message with 1s delay: %s", exception)
            time.sleep(1)
            message.requeue()
        else:
            message.ack()
            self.preprocessed_events_counter.inc()


class EnrichWorker(ConsumerProducerMixin, LoggingMixin, PrometheusWorkerMixin):
    def __init__(self, connection, enrich_event):
        self.connection = connection
        self.enrich_event = enrich_event
        self.name = "enrich worker"

    def setup_prometheus_metrics(self):
        self.enriched_events_counter = Counter(
            "enriched_events",
            "Enriched events",
            ["event_type"]
        )
        self.produced_events_counter = Counter(
            "produced_events",
            "Produced events",
            ["event_type"]
        )

    def run(self, *args, **kwargs):
        self.log_info("run")
        prometheus_port = kwargs.pop("prometheus_port")
        if prometheus_port:
            self.start_prometheus_server(prometheus_port)
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
                self.produced_events_counter.labels(event.event_type).inc()
        except Exception as exception:
            logger.exception("Requeuing message with 1s delay: %s", exception)
            time.sleep(1)
            message.requeue()
        else:
            message.ack()
            self.enriched_events_counter.labels(event.event_type).inc()


class ProcessWorker(ConsumerMixin, LoggingMixin, PrometheusWorkerMixin):
    def __init__(self, connection, process_event):
        self.connection = connection
        self.process_event = process_event
        self.name = "process worker"

    def setup_prometheus_metrics(self):
        self.processed_events_counter = Counter(
            "processed_events",
            "Processed events",
            ["event_type"]
        )

    def run(self, *args, **kwargs):
        self.log_info("run")
        prometheus_port = kwargs.pop("prometheus_port")
        if prometheus_port:
            self.start_prometheus_server(prometheus_port)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[process_events_queue],
                         accept=['json'],
                         callbacks=[self.do_process_event])]

    def do_process_event(self, body, message):
        self.log_debug("process event")
        self.process_event(body)
        message.ack()
        self.processed_events_counter.labels(body['_zentral']['type']).inc()


class StoreWorker(ConsumerMixin, LoggingMixin, PrometheusWorkerMixin):
    def __init__(self, connection, event_store):
        self.connection = connection
        self.event_store = event_store
        self.name = "store worker {}".format(self.event_store.name)
        self.input_queue = Queue(('store_events_{}'.format(self.event_store.name)).replace(" ", "_"),
                                 exchange=enriched_events_exchange,
                                 durable=True)

    def setup_prometheus_metrics(self):
        self.stored_events_counter = Counter(
            "stored_events",
            "Stored events",
            ["event_type"]
        )

    def run(self, *args, **kwargs):
        self.log_info("run")
        prometheus_port = kwargs.pop("prometheus_port")
        if prometheus_port:
            self.start_prometheus_server(prometheus_port)
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[self.input_queue],
                         accept=['json'],
                         callbacks=[self.do_store_event])]

    def do_store_event(self, body, message):
        self.log_debug("store event")
        self.event_store.store(body)
        message.ack()
        self.stored_events_counter.labels(body['_zentral']['type']).inc()


class EventQueues(object):
    def __init__(self, config_d):
        self.backend_url = config_d['backend_url']
        self.connection = Connection(self.backend_url)
        # migration TODO: remove ?
        # disconnect process_events_queue from events_exchange
        channel = self.connection.channel()
        bound_process_events_queue = process_events_queue.bind(channel)
        bound_process_events_queue.unbind_from(events_exchange)
        channel.close()

    def get_preprocess_worker(self, event_preprocessor):
        return PreprocessWorker(Connection(self.backend_url), event_preprocessor)

    def get_enrich_worker(self, enrich_event):
        return EnrichWorker(Connection(self.backend_url), enrich_event)

    def get_process_worker(self, process_event):
        return ProcessWorker(Connection(self.backend_url), process_event)

    def get_store_worker(self, event_store):
        store_worker = StoreWorker(Connection(self.backend_url), event_store)
        # migration TODO: remove ?
        # disconnect StoreWorker input_queue from events_exchange
        channel = self.connection.channel()
        bound_store_worker_input_queue = store_worker.input_queue.bind(channel)
        bound_store_worker_input_queue.unbind_from(events_exchange)
        channel.close()
        return store_worker

    def post_raw_event(self, input_queue_name, raw_event):
        exchange = Exchange(input_queue_name, type="fanout", durable=True)
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(raw_event,
                             serializer='json',
                             exchange=exchange,
                             declare=[exchange])

    def post_event(self, event):
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(event.serialize(machine_metadata=False),
                             serializer='json',
                             exchange=events_exchange,
                             declare=[events_exchange])
