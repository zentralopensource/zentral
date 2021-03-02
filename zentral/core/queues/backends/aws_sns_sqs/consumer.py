from collections import OrderedDict
import logging
import queue
import signal
import threading
import time
from .sqs import SQSDeleteThread, SQSReceiveThread


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.consumer")


class Consumer:
    def __init__(self, queue_url, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.process_message_queue = queue.Queue(maxsize=15)
        self.delete_message_queue = queue.Queue(maxsize=15)
        self.signal_received_event = threading.Event()
        self.stop_event = threading.Event()
        self._threads = [
            SQSDeleteThread(queue_url, self.stop_event, self.delete_message_queue, client_kwargs),
            SQSReceiveThread(queue_url, self.signal_received_event, self.process_message_queue, client_kwargs)
        ]

    def _handle_signal(self, signum, frame):
        if signum == signal.SIGTERM:
            signum = "SIGTERM"
        elif signum == signal.SIGINT:
            signum = "SIGINT"
        logger.debug("Received signal %s", signum)
        if not self.signal_received_event.is_set():
            logger.error("Signal %s. Initiate graceful stop.", signum)
            self.signal_received_event.set()

    def _graceful_stop(self):
        if not self.stop_event.is_set():
            logger.error("Set stop event")
            self.stop_event.set()
            for thread in self._threads:
                thread.join()
            logger.error("All threads stopped.")

    def process_event(self, routing_key, event_d):
        pass

    def _raw_process_event(self, receipt_handle, routing_key, event_d):
        try:
            self.process_event(routing_key, event_d)
        except Exception:
            logger.exception("receipt handle %s: could not process event", receipt_handle[-7:])
        else:
            logger.debug("receipt handle %s: queue for deletion", receipt_handle[-7:])
            self.delete_message_queue.put((receipt_handle, time.monotonic()))

    def run(self, *args, **kwargs):
        self.log_info("run")
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        for thread in self._threads:
            thread.start()
        while True:
            try:
                receipt_handle, routing_key, event_d = self.process_message_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to process")
                if self.signal_received_event.is_set():
                    break
            else:
                logger.debug("receipt handle %s: process new event", receipt_handle[-7:])
                self._raw_process_event(receipt_handle, routing_key, event_d)
        self._graceful_stop()


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


class ConsumerProducer(Consumer):
    max_in_flight_receipt_handle_count = 100

    def __init__(self, queue_url, client_kwargs=None):
        super().__init__(queue_url, client_kwargs)
        self.publish_message_queue = queue.Queue(maxsize=20)
        self.published_message_queue = queue.Queue(maxsize=20)
        self.in_flight_receipt_handles_lock = threading.RLock()
        self.in_flight_receipt_handles = OrderedDict()
        self._threads.append(ConsumerProducerFinalThread(self))

    def generate_events(self, routing_key, event_d):
        return []

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

    def _raw_process_event(self, receipt_handle, routing_key, event_d):
        generated_event_count = 0
        for new_routing_key, new_event_d in self.generate_events(routing_key, event_d):
            with self.in_flight_receipt_handles_lock:
                self.increment_receipt_handle_unpublished_event_count(receipt_handle)
            self.publish_message_queue.put((receipt_handle, new_routing_key, new_event_d, time.monotonic()))
            generated_event_count += 1
        if not generated_event_count:
            logger.debug("receipt handle %s: no events to publish, queue for deletion", receipt_handle[-7:])
            self.delete_message_queue.put((receipt_handle, time.monotonic()))
