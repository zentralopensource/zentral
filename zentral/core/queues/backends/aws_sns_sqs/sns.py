import logging
import queue
import threading
import boto3
from kombu.utils import json


logger = logging.getLogger("zentral.core.queues.backends.aws_sns_sqs.sns")


class SNSPublishThread(threading.Thread):
    def __init__(self, topic_arn, stop_event, in_queue, client_kwargs=None):
        if client_kwargs is None:
            client_kwargs = {}
        self.client = boto3.client("sns", **client_kwargs)
        self.topic_arn = topic_arn
        self.stop_event = stop_event
        self.in_queue = in_queue
        super().__init__()

    def run(self):
        while True:
            try:
                routing_key, event_d, event_ts = self.in_queue.get(block=True, timeout=1)
            except queue.Empty:
                logger.debug("no new event to publish")
                if self.stop_event.is_set():
                    logger.debug("publish thread gracefull exit")
                    break
            else:
                logger.debug("new event to publish %s %s", routing_key, event_ts)
                message = json.dumps(event_d)
                message_attributes = {}
                if routing_key:
                    message_attributes["zentral.routing_key"] = {
                        "DataType": "String",
                        "StringValue": routing_key,
                    }
                try:
                    response = self.client.publish(
                        TopicArn=self.topic_arn,
                        Message=message,
                        MessageAttributes=message_attributes
                    )
                except Exception:
                    logger.exception("could not publish event")
                else:
                    logger.debug("event with MessageID %s published", response["MessageId"])
