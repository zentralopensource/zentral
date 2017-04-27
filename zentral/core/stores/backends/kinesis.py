import json
import logging
import boto3
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.kinesis')


class EventStore(BaseEventStore):
    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        self.stream = config_d["stream"]
        self.region_name = config_d["region_name"]
        self.aws_access_key_id = config_d.get("aws_access_key_id")
        self.aws_secret_access_key = config_d.get("aws_secret_access_key")

    def wait_and_configure(self):
        self.client = boto3.client('kinesis',
                                   region_name=self.region_name,
                                   aws_access_key_id=self.aws_access_key_id,
                                   aws_secret_access_key=self.aws_secret_access_key)
        self.configured = True

    def store(self, event):
        self.wait_and_configure_if_necessary()
        if not isinstance(event, dict):
            event = event.serialize()
        data = json.dumps(event).encode('utf-8')
        self.client.put_record(StreamName=self.stream,
                               Data=data,
                               PartitionKey=event['_zentral']['id'])
