from datetime import datetime
import logging
import secrets
from kombu.utils import json
import pyarrow as pa
from pyarrow.fs import S3FileSystem
import pyarrow.parquet as pq
from rest_framework import serializers
from zentral.core.stores.backends.base import AWSAuthSerializer, BaseStore, serialize_needles


logger = logging.getLogger('zentral.core.stores.backends.s3_parquet')


class S3ParquetStore(BaseStore):
    kwargs_keys = (
        "bucket",
        "prefix",
        "region_name",
        "aws_access_key_id",
        "aws_secret_access_key",
        "assume_role_arn",
        "batch_size",
        "max_batch_age_seconds",
    )
    encrypted_kwargs_paths = (
        ["aws_secret_access_key"],
    )

    default_batch_size = 10000
    min_batch_size = 100
    max_batch_size = 100000
    default_max_batch_age_seconds = 300
    min_max_batch_age_seconds = 10
    max_max_batch_age_seconds = 1200

    @staticmethod
    def _get_schema():
        return pa.schema([
            pa.field('created_at', pa.timestamp('ns'), nullable=False),
            pa.field('type', pa.string(), nullable=False),
            pa.field('id', pa.string(), nullable=False),
            pa.field('tags', pa.list_(pa.string()), nullable=False),
            pa.field('needles', pa.list_(pa.string()), nullable=False),
            pa.field('serial_number', pa.string(), nullable=True),
            pa.field('metadata', pa.json_(), nullable=False),
            pa.field('payload', pa.json_(), nullable=False),
        ])

    def _get_filesystem(self):
        fs_kwargs = {}
        for fsattr, attr in (("access_key", "aws_access_key_id"),
                             ("secret_key", "aws_secret_access_key"),
                             ("region", "region_name"),
                             ("role_arn", "assume_role_arn")):
            val = getattr(self, attr, None)
            if val:
                fs_kwargs[fsattr] = val
                if fsattr == "role_arn":
                    fs_kwargs["session_name"] = "ZentralS3Parquet"
        return S3FileSystem(**fs_kwargs)

    def wait_and_configure(self):
        self._batch_index = 1
        self._writer_id = secrets.token_hex(4)
        self._schema = self._get_schema()
        self._fs = self._get_filesystem()
        self.configured = True
        logger.info("Writer ID: %s", self._writer_id)

    def _get_parquet_path(self):
        n = datetime.utcnow()
        return (
            f"{self.bucket}/{self.prefix}{n:%Y/%m/%d}/"
            f"{self._writer_id}/{self._batch_index:08d}.parquet"
        )

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        metadata = event_d.pop("_zentral")
        event_id = metadata["id"]
        event_index = metadata["index"]
        event_type = metadata.pop("type")
        created_at = metadata.pop("created_at")
        tags = metadata.pop("tags", [])
        needles = serialize_needles(metadata)
        serial_number = metadata.get("machine_serial_number")
        return {
            "created_at": datetime.fromisoformat(created_at),
            "type": event_type,
            "id": f'{event_id}_{event_index:06d}',
            "tags": tags,
            "needles": needles,
            "serial_number": serial_number,
            "metadata": json.dumps(metadata),
            "payload": json.dumps(event_d),
        }, event_id, event_index

    def store(self, event):
        raise RuntimeError("Only bulk_store is available")

    def bulk_store(self, events):
        if not events:
            return

        self.wait_and_configure_if_necessary()

        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")

        event_keys = []
        rows = []
        for event in events:
            row, event_id, event_index = self._serialize_event(event)
            event_keys.append((event_id, event_index))
            rows.append(row)

        table = pa.Table.from_pylist(rows, schema=self._schema)
        pq.write_table(table, self._get_parquet_path(), filesystem=self._fs)
        self._batch_index += 1

        yield from event_keys


# Serializers


class S3ParquetStoreSerializer(AWSAuthSerializer):
    bucket = serializers.CharField(min_length=1)
    prefix = serializers.CharField(default="")
    batch_size = serializers.IntegerField(
        default=S3ParquetStore.default_batch_size,
        min_value=S3ParquetStore.min_batch_size,
        max_value=S3ParquetStore.max_batch_size,
    )
    max_batch_age_seconds = serializers.IntegerField(
        default=S3ParquetStore.default_max_batch_age_seconds,
        min_value=S3ParquetStore.min_max_batch_age_seconds,
        max_value=S3ParquetStore.max_max_batch_age_seconds,
    )
