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
    visibility_timeout = 120
    wait_time_seconds = 10

    def __init__(self, queue_url, stop_event, out_queue, client_kwargs=None):
        logger.debug("build receive thread on SQS queue %s", queue_url)
        if client_kwargs is None:
            client_kwargs = {}
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.out_queue = out_queue
        super().__init__()

    def run(self):
        logger.debug("start receive thread on SQS queue %s", self.queue_url)
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
                logger.exception("could not receive events")
                seconds = random.uniform(10, 60)
                logger.error("retry in {:.1f}s".format(seconds))
                slices = 50
                for i in range(slices):
                    time.sleep(seconds / slices)
                    if self.stop_event.is_set():
                        break
            else:
                i = 0
                for message in response.get("Messages", []):
                    i += 1
                    receipt_handle = message['ReceiptHandle']
                    try:
                        routing_key = message['MessageAttributes']['zentral.routing_key']['StringValue']
                    except KeyError:
                        routing_key = None
                    event_d = json.loads(message['Body'])
                    self.out_queue.put((receipt_handle, routing_key, event_d))
                logger.debug("%d event(s) received and queued", i)
        logger.debug("receive thread gracefull exit")


class SQSDeleteThread(threading.Thread):
    max_number_of_messages = 10
    max_receipt_handle_age_seconds = 5

    def __init__(self, queue_url, stop_event, in_queue, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.in_queue = in_queue
        super().__init__()

    def run(self):
        entries = {}
        min_receipt_handle_ts = None
        while True:
            try:
                receipt_handle, receipt_handle_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to delete")
                if entries:
                    if self.stop_event.is_set():
                        logger.debug("delete events before gracefull exit")
                        self.delete_entries(entries)
                        entries = {}
                        min_receipt_handle_ts = None
                    else:
                        if time.time() > min_receipt_handle_ts + self.max_receipt_handle_age_seconds:
                            logger.debug("delete events because max event age reached")
                            self.delete_entries(entries)
                            entries = {}
                            min_receipt_handle_ts = None
                if self.stop_event.is_set():
                    logger.debug("delete thread gracefull exit")
                    break
            else:
                logger.debug("new event to delete %s %s", receipt_handle, receipt_handle_ts)
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
        logger.debug("delete %s event(s)", len(entries))
        try:
            response = self.client.delete_message_batch(
                QueueUrl=self.queue_url,
                Entries=list(entries.values())
            )
        except Exception:
            logger.exception("could not delete event(s)")
        else:
            total_entries = len(entries)
            logger.debug("%s/%s event(s) deleted", len(response.get("Successful", [])), total_entries)
            i = 0
            for failed_entry in response.get("Failed", []):
                i += 1
                logger.debug("event deletion error: %s", failed_entry)
            if i:
                logger.error("%s/%s event deletion error(s)", i, total_entries)


class SQSSendThread(threading.Thread):
    max_number_of_messages = 10
    max_event_age_seconds = 5

    def __init__(self, queue_url, stop_event, in_queue, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.client = boto3.client("sqs", **client_kwargs)
        self.queue_url = queue_url
        self.stop_event = stop_event
        self.in_queue = in_queue
        super().__init__()

    def run(self):
        entries = {}
        min_event_ts = None
        while True:
            logger.debug("%s event(s) to send", len(entries))
            try:
                routing_key, event_d, event_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to send")
                if entries:
                    if self.stop_event.is_set():
                        logger.debug("send current event(s) before gracefull exit")
                        self.send_entries(entries)
                        entries = {}
                        min_event_ts = None
                    else:
                        if time.time() > min_event_ts + self.max_event_age_seconds:
                            logger.debug("send %s event(s) because max event age reached", len(entries))
                            self.send_entries(entries)
                            entries = {}
                            min_event_ts = None
                if self.stop_event.is_set():
                    logger.debug("send thread gracefull exit")
                    break
            else:
                logger.debug("new event to send %s %s", routing_key, event_ts)
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
                entries[entry_id] = entry
                min_event_ts = min(min_event_ts or event_ts, event_ts)
                if len(entries) == self.max_number_of_messages:
                    self.send_entries(entries)
                    entries = {}
                    min_event_ts = None

    def send_entries(self, entries):
        logger.debug("send %s event(s)", len(entries))
        try:
            response = self.client.send_message_batch(
                QueueUrl=self.queue_url,
                Entries=list(entries.values())
            )
        except Exception:
            logger.exception("could not send event(s)")
        else:
            total_entries = len(entries)
            logger.debug("%s/%s event(s) sent", len(response.get("Successful", [])), total_entries)
            i = 0
            for failed_entry in response.get("Failed", []):
                i += 1
                logger.debug("event sending error: %s", failed_entry)
            if i:
                logger.error("%s/%s event sending error(s)", i, total_entries)
