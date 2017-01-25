import logging
from kombu import Connection, Consumer, Exchange, Queue
from kombu.mixins import ConsumerMixin, ConsumerProducerMixin
from kombu.pools import producers
from zentral.core.probes.conf import all_probes


logger = logging.getLogger('zentral.core.queues.backends.kombu')


store_events_exchange = Exchange('store_events', type="fanout", durable=True)
store_events_queue = Queue('store_events',
                           exchange=store_events_exchange,
                           durable=True)

process_events_exchange = Exchange('process_events', type="fanout", durable=True)
process_events_queue = Queue('process_events',
                             exchange=process_events_exchange,
                             durable=True)

probes_exchange = Exchange('probes', type='fanout', durable=True)


class PreprocessorWorker(ConsumerProducerMixin):
    def __init__(self, connection, event_preprocessor):
        self.connection = connection
        self.event_preprocessor = event_preprocessor
        input_exchange = Exchange(event_preprocessor.input_queue_name, type="fanout", durable=True)
        self.input_queue = Queue(event_preprocessor.input_queue_name, exchange=input_exchange, durable=True)
        self.name = "preprocessor worker {}".format(self.event_preprocessor.name)

    def log_info(self, msg):
        logger.info("{} - {}".format(self.name, msg))

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        return [Consumer(default_channel,
                         queues=[self.input_queue],
                         accept=['json'],
                         callbacks=[self.process_raw_event])]

    def process_raw_event(self, body, message):
        self.log_info("process raw event")
        for event in self.event_preprocessor.process_raw_event(body):
            self.producer.publish(event.serialize(machine_metadata=False),
                                  serializer='json',
                                  exchange=store_events_exchange,
                                  declare=[store_events_exchange])
        message.ack()


class StoreWorker(ConsumerProducerMixin):
    def __init__(self, connection, event_store):
        self.connection = connection
        self.channel2 = None
        self.event_store = event_store
        self.name = "store worker {}".format(self.event_store.name)

    def log_info(self, msg):
        logger.info("{} - {}".format(self.name, msg))

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        self.channel2 = default_channel.connection.channel()
        return [Consumer(default_channel,
                         queues=[store_events_queue],
                         accept=['json'],
                         callbacks=[self.store_event]),
                Consumer(self.channel2,
                         queues=[Queue(exchange=probes_exchange,
                                       auto_delete=True,
                                       durable=False)],
                         accept=['json'],
                         callbacks=[self.clear_probes_cache])]

    def on_consumer_end(self, connection, default_channel):
        self.log_info("consumer end")
        if self.channel2:
            self.channel2.close()

    def store_event(self, body, message):
        self.log_info("store event")
        self.event_store.store(body)
        self.producer.publish(body,
                              serializer='json',
                              exchange=process_events_exchange,
                              declare=[process_events_exchange])
        message.ack()

    def clear_probes_cache(self, body, message):
        self.log_info("clear probes cache")
        all_probes.clear()
        message.ack()


class ProcessorWorker(ConsumerMixin):
    def __init__(self, connection, event_processor):
        self.connection = connection
        self.channel2 = None
        self.event_processor = event_processor
        self.name = "processor worker"

    def log_info(self, msg):
        logger.info("{} - {}".format(self.name, msg))

    def run(self, *args, **kwargs):
        self.log_info("run")
        super().run(*args, **kwargs)

    def get_consumers(self, _, default_channel):
        self.channel2 = default_channel.connection.channel()
        return [Consumer(default_channel,
                         queues=[process_events_queue],
                         accept=['json'],
                         callbacks=[self.process_event]),
                Consumer(self.channel2,
                         queues=[Queue(exchange=probes_exchange,
                                       auto_delete=True,
                                       durable=False)],
                         accept=['json'],
                         callbacks=[self.clear_probes_cache])]

    def on_consumer_end(self, connection, default_channel):
        self.log_info("consumer end")
        if self.channel2:
            self.channel2.close()

    def process_event(self, body, message):
        self.log_info("process event")
        self.event_processor.process(body)
        message.ack()

    def clear_probes_cache(self, body, message):
        self.log_info("clear probes cache")
        all_probes.clear()
        message.ack()


class EventQueues(object):
    def __init__(self, config_d):
        self.backend_url = config_d['backend_url']
        self.connection = Connection(self.backend_url)

    def get_preprocessor_worker(self, event_preprocessor):
        return PreprocessorWorker(Connection(self.backend_url), event_preprocessor)

    def get_store_worker(self, event_store):
        return StoreWorker(Connection(self.backend_url), event_store)

    def get_processor_worker(self, event_processor):
        return ProcessorWorker(Connection(self.backend_url), event_processor)

    def signal_probe_change(self):
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish("probe_change",
                             serializer='json',
                             exchange=probes_exchange,
                             declare=[probes_exchange])

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
                             exchange=store_events_exchange,
                             declare=[store_events_exchange])
