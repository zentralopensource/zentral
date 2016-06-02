from kombu import Connection, Exchange, Queue
from kombu.mixins import ConsumerMixin
from kombu.pools import producers
from zentral.core.probes.conf import all_probes

store_events_exchange = Exchange('store_events', type="fanout", durable=True)
store_events_queue = Queue('store_events',
                           exchange=store_events_exchange,
                           durable=True)

process_events_exchange = Exchange('process_events', type="fanout", durable=True)
process_events_queue = Queue('process_events',
                             exchange=process_events_exchange,
                             durable=True)

probes_exchange = Exchange('probes', type='fanout', durable=True)


class StoreWorker(ConsumerMixin):
    def __init__(self, connection, event_store):
        self.connection = connection
        self.event_store = event_store

    def get_consumers(self, Consumer, channel):
        return [Consumer(queues=[store_events_queue],
                         accept=['json'],
                         callbacks=[self.store_event]),
                Consumer(queues=[Queue(exchange=probes_exchange,
                                       auto_delete=True,
                                       durable=False)],
                         accept=['json'],
                         callbacks=[self.clear_probes_cache])]

    def store_event(self, body, message):
        from zentral.core.events import event_from_event_d
        event = event_from_event_d(body)
        self.event_store.store(event)
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(body,
                             serializer='json',
                             exchange=process_events_exchange,
                             declare=[process_events_exchange])
        message.ack()

    def clear_probes_cache(self, body, message):
        print("STORE WORKER CLEAR PROBES CACHE")
        all_probes.clear()
        message.ack()


class ProcessorWorker(ConsumerMixin):
    def __init__(self, connection, event_processor):
        self.connection = connection
        self.event_processor = event_processor

    def get_consumers(self, Consumer, channel):
        return [Consumer(queues=[process_events_queue],
                         accept=['json'],
                         callbacks=[self.process_event]),
                Consumer(queues=[Queue(exchange=probes_exchange,
                                       auto_delete=True,
                                       durable=False)],
                         accept=['json'],
                         callbacks=[self.clear_probes_cache])]

    def process_event(self, body, message):
        from zentral.core.events import event_from_event_d
        event = event_from_event_d(body)
        self.event_processor.process(event)
        message.ack()

    def clear_probes_cache(self, body, message):
        print("PROCESSOR WORKER CLEAR PROBES CACHE")
        all_probes.clear()
        message.ack()


class EventQueues(object):
    def __init__(self, config_d):
        self.backend_url = config_d['backend_url']
        self.connection = Connection(self.backend_url)

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

    def post_event(self, event):
        with producers[self.connection].acquire(block=True) as producer:
            producer.publish(event.serialize(machine_metadata=False),
                             serializer='json',
                             exchange=store_events_exchange,
                             declare=[store_events_exchange])
