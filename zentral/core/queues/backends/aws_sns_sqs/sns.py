import logging
import queue
import threading
import boto3
from kombu.utils import json


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.sns")


class SNSPublishThread(threading.Thread):
    def __init__(self, thread_id, topic_arn, stop_event, in_queue, out_queue, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.client = boto3.client("sns", **client_kwargs)
        self.topic_arn = topic_arn
        self.stop_event = stop_event
        self.in_queue = in_queue
        self.out_queue = out_queue
        super().__init__(name=f"SNS publish thread {thread_id}")

    def run(self):
        logger.info("[%s] start on topic %s", self.name, self.topic_arn)
        while True:
            try:
                receipt_handle, routing_key, event_d, event_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("[%s] no new event to publish", self.name)
                if self.stop_event.is_set():
                    logger.info("[%s] graceful exit", self.name)
                    break
            else:
                logger.debug("[%s] new event to publish %s %s", self.name, routing_key, event_ts)
                message = json.dumps(event_d)
                message_attributes = {}
                if routing_key:
                    message_attributes["zentral.routing_key"] = {
                        "DataType": "String",
                        "StringValue": routing_key,
                    }
                else:
                    try:
                        message_attributes["zentral.type"] = {
                            "DataType": "String",
                            "StringValue": event_d['_zentral']['type']
                        }
                    except KeyError:
                        pass
                try:
                    response = self.client.publish(
                        TopicArn=self.topic_arn,
                        Message=message,
                        MessageAttributes=message_attributes
                    )
                except Exception:
                    logger.exception("[%s] could not publish event", self.name)
                else:
                    logger.debug("[%s] event with MessageID %s published", self.name, response["MessageId"])
                    self.out_queue.put(receipt_handle)
                    logger.debug("[%s] receipt handle %s: put to out queue", self.name, receipt_handle[-7:])
