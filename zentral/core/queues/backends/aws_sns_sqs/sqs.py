import logging
import queue
import random
import threading
import time
import uuid
import boto3
from kombu.utils import json


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.sqs")


class SQSReceiveThread(threading.Thread):
    attribute_names = ['All']
    message_attribute_names = ['All']
    max_number_of_messages = 10
    wait_time_seconds = 10

    def __init__(self, queue_url, stop_event, out_queue, client_kwargs, visibility_timeout):
        logger.debug("build receive thread on SQS queue %s", queue_url)
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.out_queue = out_queue
        self.visibility_timeout = visibility_timeout
        super().__init__(name="SQS receive thread")

    def run(self):
        logger.info("[%s] start on queue %s", self.name, self.queue_url)
        while not self.stop_event.is_set():
            try:
                response = self.client.receive_message(
                    QueueUrl=self.queue_url,
                    AttributeNames=self.attribute_names,
                    MessageAttributeNames=self.message_attribute_names,
                    MaxNumberOfMessages=self.max_number_of_messages,
                    VisibilityTimeout=self.visibility_timeout,
                    WaitTimeSeconds=self.wait_time_seconds
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
                messages = response.get("Messages", [])
                for message in messages:
                    if self.stop_event.is_set():
                        break
                    i += 1
                    receipt_handle = message['ReceiptHandle']
                    try:
                        routing_key = message['MessageAttributes']['zentral.routing_key']['StringValue']
                    except KeyError:
                        routing_key = None
                    event_d = json.loads(message['Body'])
                    while True:
                        try:
                            self.out_queue.put((receipt_handle, routing_key, event_d), timeout=1)
                        except queue.Full:
                            if self.stop_event.is_set():
                                break
                        else:
                            break
                logger.debug("[%s] %d/%d event(s) received and queued", self.name, i, len(messages))


class SQSDeleteThread(threading.Thread):
    max_number_of_messages = 10
    max_receipt_handle_age_seconds = 5

    def __init__(self, queue_url, stop_event, in_queue, client_kwargs):
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.in_queue = in_queue
        super().__init__(name="SQS delete thread")

    def run(self):
        logger.info("[%s] start on queue %s", self.name, self.queue_url)
        entries = {}
        min_receipt_handle_ts = None
        while True:
            try:
                receipt_handle, receipt_handle_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new events", self.name)
                if entries:
                    if self.stop_event.is_set():
                        logger.debug("[%s] delete events before graceful exit", self.name)
                        self.delete_entries(entries)
                        entries = {}
                        min_receipt_handle_ts = None
                    else:
                        if time.monotonic() > min_receipt_handle_ts + self.max_receipt_handle_age_seconds:
                            logger.debug("[%s] delete events because max event age reached", self.name)
                            self.delete_entries(entries)
                            entries = {}
                            min_receipt_handle_ts = None
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                logger.debug("[%s] receipt handle %s: new event to delete %s",
                             self.name, receipt_handle[-7:], receipt_handle_ts)
                entry_id = str(uuid.uuid4())
                entry = {"Id": entry_id,
                         "ReceiptHandle": receipt_handle}
                entries[entry_id] = entry
                min_receipt_handle_ts = min(receipt_handle_ts, min_receipt_handle_ts or receipt_handle_ts)
                if len(entries) == self.max_number_of_messages:
                    self.delete_entries(entries)
                    entries = {}
                    min_receipt_handle_ts = None

    def delete_entries(self, entries):
        logger.debug("[%s] delete %s event(s)", self.name, len(entries))
        try:
            response = self.client.delete_message_batch(
                QueueUrl=self.queue_url,
                Entries=list(entries.values())
            )
        except Exception:
            logger.exception("could not delete event(s)")
        else:
            entry_count = len(entries)
            logger.debug("[%s] %s/%s event(s) deleted", self.name, len(response.get("Successful", [])), entry_count)
            i = 0
            for failed_entry in response.get("Failed", []):
                i += 1
                logger.debug("[%s] event deletion error: %s", self.name, failed_entry)
            if i:
                logger.error("[%s] %s/%s event deletion error(s)", self.name, i, entry_count)


class SQSSendThread(threading.Thread):
    max_number_of_messages = 10
    max_event_age_seconds = 5

    def __init__(self, queue_url, stop_event, in_queue, out_queue, client_kwargs):
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.in_queue = in_queue
        self.out_queue = out_queue
        super().__init__(name="SQS send thread")

    def run(self):
        logger.info("[%s] start on queue %s", self.name, self.queue_url)
        self.entries = {}
        self.min_event_ts = None
        while True:
            logger.debug("[%s] %s event(s) to send", self.name, len(self.entries))
            try:
                receipt_handle, routing_key, event_d, event_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new event to send", self.name)
                if self.entries:
                    if self.stop_event.is_set():
                        logger.debug("[%s] send current event(s) before graceful exit", self.name)
                        self.send_entries()
                    else:
                        if time.monotonic() > self.min_event_ts + self.max_event_age_seconds:
                            logger.debug("[%s] send %s event(s) because max event age reached",
                                         self.name, len(self.entries))
                            self.send_entries()
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                logger.debug("[%s] new event to send %s %s", self.name, routing_key, event_ts)
                entry_id = str(uuid.uuid4())
                entry = {"Id": entry_id,
                         "MessageBody": json.dumps(event_d)}
                if routing_key:
                    entry["MessageAttributes"] = {
                        "zentral.routing_key": {
                            "DataType": "String",
                            "StringValue": routing_key
                        }
                    }
                self.entries[entry_id] = (receipt_handle, entry)
                self.min_event_ts = min(self.min_event_ts or event_ts, event_ts)
                if len(self.entries) == self.max_number_of_messages:
                    self.send_entries()

    def send_entries(self):
        entry_count = len(self.entries)
        logger.debug("[%s] send %s event(s)", self.name, entry_count)
        try:
            response = self.client.send_message_batch(
                QueueUrl=self.queue_url,
                Entries=list(entry for _, entry in self.entries.values())
            )
        except Exception:
            logger.exception("[%s] could not send event(s)", self.name)
        else:
            successful_entry_count = 0
            for successful_entry in response.get("Successful", []):
                successful_entry_count += 1
                if self.out_queue:
                    try:
                        receipt_handle, _ = self.entries[successful_entry["Id"]]
                    except KeyError:
                        logger.error("[%s] could not put receipt receipt handle to out queue", self.name)
                    else:
                        if receipt_handle:
                            self.out_queue.put(receipt_handle)
                            logger.debug("[%s] receipt handle %s: put to out queue", self.name, receipt_handle[-7:])
            logger.debug("[%s] %s/%s event(s) sent", self.name, successful_entry_count, entry_count)
            failed_entry_count = 0
            for failed_entry in response.get("Failed", []):
                failed_entry_count += 1
                logger.error("[%s] event sending error - sender fault: %s code: %s",
                             self.name, failed_entry.get("SenderFault", "-"), failed_entry.get("Code", "-"))
            if failed_entry_count:
                logger.error("[%s] %s/%s event sending error(s)", self.name, failed_entry_count, entry_count)
        # update state
        self.entries = {}
        self.min_event_ts = None
