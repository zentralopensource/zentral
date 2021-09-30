from collections import deque, OrderedDict
import logging
import queue
import signal
import threading
import time
from .sqs import SQSDeleteThread, SQSReceiveThread


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.consumer")


# BaseConsumer


class BaseConsumer:
    def __init__(self, queue_url, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.process_message_queue = queue.Queue(maxsize=15)
        self.delete_message_queue = queue.Queue(maxsize=15)
        self.stop_receiving_event = threading.Event()
        self.stop_event = threading.Event()
        self._threads = [
            SQSReceiveThread(queue_url, self.stop_receiving_event, self.process_message_queue, client_kwargs),
            SQSDeleteThread(queue_url, self.stop_event, self.delete_message_queue, client_kwargs)
        ]

    def _handle_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            signum = "SIGTERM"
        elif signum == signal.SIGINT:
            signum = "SIGINT"
        logger.debug("received signal %s", signum)
        if not self.stop_receiving_event.is_set():
            logger.error("signal %s - stop receiving events", signum)
            self.stop_receiving_event.set()

    def run(self, *args, **kwargs):
        exit_status = 0
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        for thread in self._threads:
            thread.start()
        try:
            self.start_run_loop()
        except Exception:
            exit_status = 1
            logger.exception("%s: run loop exception", self.name)
            if not self.stop_receiving_event.is_set():
                logger.error("%s: stop receiving", self.name)
                self.stop_receiving_event.set()
        # graceful stop
        if not self.stop_event.is_set():
            logger.error("Set stop event")
            self.stop_event.set()
            for thread in self._threads:
                thread.join()
            logger.error("All threads stopped.")
        return exit_status

    def start_run_loop(self):
        raise NotImplementedError

    def skip_event(self, receipt_handle, event_d):
        # to override in the sub-classes if necessary
        return False


# Consumer


class Consumer(BaseConsumer):
    def start_run_loop(self):
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to process")
                if self.stop_receiving_event.is_set():
                    break
            else:
                if self.skip_event(receipt_handle, event_d):
                    logger.debug("receipt handle %s: event skipped", receipt_handle[-7:])
                else:
                    logger.debug("receipt handle %s: process new event", receipt_handle[-7:])
                    self.process_event(routing_key, event_d)
                logger.debug("receipt handle %s: queue for deletion", receipt_handle[-7:])
                self.delete_message_queue.put((receipt_handle, time.monotonic()))

    def process_event(self, routing_key, event_d):
        # to be implemented in the sub-classes
        raise NotImplementedError


# ConcurrentConsumer


class ConcurrentConsumerFinalThread(threading.Thread):
    def __init__(self, concurrent_consumer):
        self.processed_event_queue = concurrent_consumer.processed_event_queue
        self.delete_message_queue = concurrent_consumer.delete_message_queue
        self.stop_event = concurrent_consumer.stop_event
        self.update_metrics_cb = concurrent_consumer.update_metrics
        super().__init__(name="ConcurrentConsumer final thread")

    def run(self):
        while True:
            try:
                receipt_handle, success, event_type, process_time = self.processed_event_queue.get(block=True,
                                                                                                   timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new processed event", self.name)
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                if success:
                    logger.debug("[%s] receipt handle %s: new processed event", self.name, receipt_handle[-7:])
                    self.delete_message_queue.put((receipt_handle, time.monotonic()))
                else:
                    logger.error("[%s] receipt handle %s: could not process event", self.name, receipt_handle[-7:])
                self.update_metrics_cb(success, event_type, process_time)


class ConcurrentConsumer(BaseConsumer):
    def __init__(self, queue_url, concurrency, client_kwargs=None):
        super().__init__(queue_url, client_kwargs)
        self.concurrency = concurrency
        self.process_event_queue = queue.Queue(maxsize=concurrency)
        self.processed_event_queue = queue.Queue(maxsize=concurrency)
        process_thread_constructor = self.get_process_thread_constructor()
        for i in range(concurrency):
            self._threads.append(
                process_thread_constructor(
                    i + 1,
                    self.process_event_queue,
                    self.processed_event_queue,
                    self.stop_event
                )
            )
        self._threads.append(ConcurrentConsumerFinalThread(self))

    def start_run_loop(self):
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to process")
                if self.stop_receiving_event.is_set():
                    break
            else:
                if self.skip_event(receipt_handle, event_d):
                    logger.debug("receipt handle %s: event skipped", receipt_handle[-7:])
                    self.delete_message_queue.put((receipt_handle, time.monotonic()))
                else:
                    logger.debug("receipt handle %s: queue new event", receipt_handle[-7:])
                    self.process_event_queue.put((receipt_handle, routing_key, event_d))


# BatchConsumer


class BatchConsumer(BaseConsumer):
    max_event_age_seconds = 5

    def __init__(self, queue_url, batch_size, client_kwargs=None):
        super().__init__(queue_url, client_kwargs)
        self.batch_size = batch_size
        self.batch = deque()
        self.batch_start_ts = None

    def start_run_loop(self):
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to process")
                if self.batch:
                    if self.stop_receiving_event.is_set():
                        logger.debug("process events before graceful exit")
                        self._process_batch()
                    elif time.monotonic() > self.batch_start_ts + self.max_event_age_seconds:
                        logger.debug("process events because max event age reached")
                        self._process_batch()
                if self.stop_receiving_event.is_set():
                    break
            else:
                if self.skip_event(receipt_handle, event_d):
                    logger.debug("receipt handle %s: event skipped", receipt_handle[-7:])
                    self.delete_message_queue.put((receipt_handle, time.monotonic()))
                    if self.batch and time.monotonic() > self.batch_start_ts + self.max_event_age_seconds:
                        logger.debug("process events because max event age reached")
                        self._process_batch()
                else:
                    logger.debug("receipt handle %s: queue new event for batch processing", receipt_handle[-7:])
                    self.batch.append((receipt_handle, routing_key, event_d))
                    if self.batch_start_ts is None:
                        self.batch_start_ts = time.monotonic()
                    if len(self.batch) >= self.batch_size:
                        self._process_batch()

    def _process_batch(self):
        for receipt_handle in self.process_events(self.batch):
            self.delete_message_queue.put((receipt_handle, time.monotonic()))
        self.batch_start_ts = None

    def process_events(self, batch):
        # to be implemented in the sub-classes
        # must be an iterator yielding the receipt handles to acknowledge
        raise NotImplementedError


# ConsumerProducer


class ConsumerProducerFinalThread(threading.Thread):
    def __init__(self, consumer_producer):
        self.stop_event = consumer_producer.stop_event
        self.in_queue = consumer_producer.published_message_queue
        self.out_queue = consumer_producer.delete_message_queue
        self.callback = consumer_producer.decrement_receipt_handle_unpublished_event_count
        super().__init__(name="Consumer/Producer final thread")

    def run(self):
        while True:
            try:
                receipt_handle = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new published event", self.name)
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                logger.debug("[%s] receipt handle %s: new published event", self.name, receipt_handle[-7:])
                if self.callback(receipt_handle):
                    logger.debug("[%s] receipt handle %s: no more unpublished events", self.name, receipt_handle[-7:])
                    self.out_queue.put((receipt_handle, time.monotonic()))
                else:
                    logger.debug("[%s] receipt handle %s: still waiting for some unpublished events",
                                 self.name, receipt_handle[-7:])


class ConsumerProducer(BaseConsumer):
    max_in_flight_receipt_handle_count = 100

    def __init__(self, queue_url, client_kwargs=None):
        super().__init__(queue_url, client_kwargs)
        self.publish_message_queue = queue.Queue(maxsize=20)
        self.published_message_queue = queue.Queue(maxsize=20)
        self.in_flight_receipt_handles_lock = threading.RLock()
        self.in_flight_receipt_handles = OrderedDict()
        self._threads.append(ConsumerProducerFinalThread(self))

    def increment_receipt_handle_unpublished_event_count(self, receipt_handle):
        logger.debug("receipt handle %s: increment unpublished event count", receipt_handle[-7:])
        new_count = self.in_flight_receipt_handles.get(receipt_handle, 0) + 1
        logger.debug("receipt handle %s: %d (+1) unpublished events", receipt_handle[-7:], new_count)
        self.in_flight_receipt_handles[receipt_handle] = new_count
        self.in_flight_receipt_handles.move_to_end(receipt_handle)
        # do some maintainance, to avoid memory issues in case of a bug
        in_flight_receipt_handle_count = len(self.in_flight_receipt_handles)
        logger.debug("%d in-flight receipt handles", in_flight_receipt_handle_count)
        if in_flight_receipt_handle_count > self.max_in_flight_receipt_handle_count:
            # need to purge the older receipt handles
            logger.error("%d > %d in-flight receipt handles",
                         in_flight_receipt_handle_count,
                         self.max_in_flight_receipt_handle_count)
            for _ in range(in_flight_receipt_handle_count - self.max_in_flight_receipt_handle_count):
                k, v = self.in_flight_receipt_handles.popitem(last=False)
                logger.error("receipt handle %s with %s in-flight events evicted", k, v)

    def decrement_receipt_handle_unpublished_event_count(self, receipt_handle):
        logger.debug("receipt handle %s: decrement unpublished event count", receipt_handle[-7:])
        with self.in_flight_receipt_handles_lock:
            try:
                current_count = self.in_flight_receipt_handles[receipt_handle]
            except KeyError:
                logger.error("unknown receipt handle %s!", receipt_handle[-7:])
                return False
            new_count = current_count - 1
            logger.debug("receipt handle %s: %d (-1) unpublished events", receipt_handle[-7:], new_count)
            if new_count <= 0:
                if new_count < 0:
                    logger.error("receipt handle %s: %d < 0 unpublished events", receipt_handle[-7:], new_count)
                logger.debug("receipt handle %s: no more unpublished events", receipt_handle[-7:])
                del self.in_flight_receipt_handles[receipt_handle]
                logger.debug("%d in-flight receipt handles", len(self.in_flight_receipt_handles))
                return True
            else:
                self.in_flight_receipt_handles[receipt_handle] = new_count
                self.in_flight_receipt_handles.move_to_end(receipt_handle)
                return False

    def start_run_loop(self):
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to process")
                if self.stop_receiving_event.is_set():
                    break
            else:
                logger.debug("receipt handle %s: process new event", receipt_handle[-7:])
                generated_event_count = 0
                for new_routing_key, new_event_d in self.generate_events(routing_key, event_d):
                    with self.in_flight_receipt_handles_lock:
                        self.increment_receipt_handle_unpublished_event_count(receipt_handle)
                    self.publish_message_queue.put((receipt_handle, new_routing_key, new_event_d, time.monotonic()))
                    generated_event_count += 1
                if not generated_event_count:
                    logger.debug("receipt handle %s: no events to publish, queue for deletion", receipt_handle[-7:])
                    self.delete_message_queue.put((receipt_handle, time.monotonic()))

    def generate_events(self, routing_key, event_d):
        # must return an iterable other the generated events
        raise NotImplementedError
