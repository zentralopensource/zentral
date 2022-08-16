import logging
import boto3
from kombu.utils import json
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.stores.backends.base import BaseEventStore
from zentral.utils.boto3 import make_refreshable_assume_role_session


logger = logging.getLogger('zentral.core.stores.backends.kinesis')


class EventStore(BaseEventStore):
    max_batch_size = 500

    def __init__(self, config_d):
        super(EventStore, self).__init__(config_d)
        self.stream = config_d["stream"]
        self.region_name = config_d["region_name"]
        self.credentials = {}
        for k in ("aws_access_key_id", "aws_secret_access_key"):
            v = config_d.get(k)
            if v:
                self.credentials[k] = v
        self.assume_role_arn = config_d.get("assume_role_arn")
        self.serialization_format = config_d.get("serialization_format", "zentral")
        if self.serialization_format not in ("zentral", "firehose_v1"):
            raise ImproperlyConfigured("Unknown serialization format")

    def wait_and_configure(self):
        session = boto3.Session(**self.credentials)
        if self.assume_role_arn:
            logger.info("Assume role %s", self.assume_role_arn)
            session = make_refreshable_assume_role_session(
                session,
                {"RoleArn": self.assume_role_arn,
                 "RoleSessionName": "ZentralStoreKinesis"}
            )
        self.client = session.client('kinesis', region_name=self.region_name)
        self.configured = True

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        event_id = event_d['_zentral']['id']
        event_index = event_d['_zentral']['index']
        partition_key = f"{event_id}{event_index}"
        if self.serialization_format == "firehose_v1":
            metadata = event_d.pop("_zentral")
            event_type = metadata.pop("type")
            created_at = metadata.pop("created_at")
            tags = metadata.pop("tags", [])
            objects = metadata.pop("objects", {})
            serial_number = metadata.pop("machine_serial_number", None)
            event_d = {
                "type": event_type,
                "created_at": created_at,
                "tags": tags,
                "probes": [probe_d["pk"] for probe_d in metadata.get("probes", [])],
                "objects": [f"{k}:{v}" for k in objects for v in objects[k]],
                "metadata": json.dumps(metadata),
                "payload": json.dumps(event_d),
                "serial_number": serial_number
            }
        return json.dumps(event_d).encode("utf-8"), partition_key, event_id, event_index

    def store(self, event):
        self.wait_and_configure_if_necessary()
        data, partition_key, _, _ = self._serialize_event(event)
        return self.client.put_record(StreamName=self.stream,
                                      Data=data,
                                      PartitionKey=partition_key)

    def bulk_store(self, events):
        self.wait_and_configure_if_necessary()

        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")

        event_keys = []
        records = []
        for event in events:
            data, partition_key, event_id, event_index = self._serialize_event(event)
            event_keys.append((event_id, event_index))
            records.append({'Data': data, 'PartitionKey': partition_key})
        if not records:
            return

        response = self.client.put_records(Records=records, StreamName=self.stream)
        failed_record_count = response.get("FailedRecordCount", 0)
        if failed_record_count == 0:
            # shortcut
            yield from event_keys
            return
        logger.warning("%s failed record(s)", failed_record_count)
        for key, record in zip(event_keys, response.get("Records", [])):
            if record.get("SequenceNumber") and record.get("ShardId"):
                yield key
