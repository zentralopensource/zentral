import json
import os.path
import shutil
from unittest.mock import patch
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from pyarrow.fs import LocalFileSystem
from accounts.events import EventMetadata, EventRequest, LoginEvent
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.s3_parquet import S3ParquetStore, S3ParquetStoreSerializer
from zentral.core.stores.serializers import StoreProvisioningSerializer
from .utils import build_login_event, force_store


class S3ParquetStoreTestCase(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (
            ("bucket", "123"),
            ("prefix", "yolo/"),
            ("region_name", "us-east-1"),
            ("aws_access_key_id", "yolo"),
            ("aws_secret_access_key", "fomo"),
            ("batch_size", 17),
            ("max_batch_age_seconds", 26),
        ):
            if arg not in kwargs:
                kwargs[arg] = default
        if "assume_role_arn" in kwargs:
            kwargs.pop("aws_access_key_id", None)
            kwargs.pop("aws_secret_access_key", None)
        return force_store(backend=StoreBackend.S3Parquet, backend_kwargs=kwargs)

    # file system options

    @patch("zentral.core.stores.backends.s3_parquet.S3FileSystem")
    def test_assume_role_fs_options(self, s3_fs):
        s3_fs.side_effect = lambda *args, **kwargs: kwargs
        store = self.get_store(assume_role_arn="haha")
        store.wait_and_configure_if_necessary()
        self.assertEqual(
            store._fs,
            {'region': 'us-east-1', 'role_arn': 'haha', 'session_name': 'ZentralS3Parquet'}
        )

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, S3ParquetStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, S3ParquetStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'bucket': '123',
             'prefix': 'yolo/',
             'region_name': 'us-east-1',
             'aws_access_key_id': 'yolo',
             'aws_secret_access_key': 'noop$Zm9tbw==',  # "encrypted"
             'batch_size': 17,
             'max_batch_age_seconds': 26},
        )

    def test_backend_serialize_for_event_with_access_key(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'S3_PARQUET',
             'backend_kwargs': {
                 'bucket': '123',
                 'prefix': 'yolo/',
                 'region_name': 'us-east-1',
                 'aws_access_key_id': 'yolo',
                 'aws_secret_access_key_hash': '48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671',
                 'batch_size': 17,
                 'max_batch_age_seconds': 26,
             },
             'created_at': store.instance.created_at,
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [{'name': role.name, 'pk': role.pk}],
             'name': store.instance.name,
             'pk': str(store.instance.pk),
             'provisioning_uid': store.instance.provisioning_uid,
             'updated_at': store.instance.updated_at}
        )

    def test_backend_serialize_for_event_with_role_arn(self):
        store = self.get_store(assume_role_arn="arn::role")
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'S3_PARQUET',
             'backend_kwargs': {
                 'assume_role_arn': 'arn::role',
                 'bucket': '123',
                 'prefix': 'yolo/',
                 'region_name': 'us-east-1',
                 'batch_size': 17,
                 'max_batch_age_seconds': 26,
             },
             'created_at': store.instance.created_at,
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [{'name': role.name, 'pk': role.pk}],
             'name': store.instance.name,
             'pk': str(store.instance.pk),
             'provisioning_uid': store.instance.provisioning_uid,
             'updated_at': store.instance.updated_at}
        )

    # event serialization

    def _test_serialization(self, serialize):
        m_uuid = uuid.uuid4()
        m_index = 3
        metadata = EventMetadata(
            uuid=m_uuid,
            index=m_index,
            objects={"osquery_enrollment": [(19,)]},
            probes=[{"pk": 18, "name": "fomo"}],
            request=EventRequest(user_agent="user_agent", ip="203.0.113.10"),
            tags=["yolo", "fomo"]
        )
        username = get_random_string(12)
        event = LoginEvent(metadata, {"user": {"username": username}})
        if serialize:
            event = event.serialize()
        store = self.get_store()
        serialized_event, event_id, event_index = store._serialize_event(event)
        self.assertEqual(event_id, str(m_uuid))
        self.assertEqual(event_index, m_index)
        serialized_event.pop('created_at')
        self.assertEqual(
            json.loads(serialized_event.pop("metadata")),
            {'id': str(m_uuid),
             'index': 3,
             'namespace': 'zentral',
             'objects': {'osquery_enrollment': ['19']},
             'probes': [{'name': 'fomo', 'pk': 18}],
             'request': {'ip': '203.0.113.10', 'user_agent': 'user_agent'}},
        )
        self.assertEqual(
            json.loads(serialized_event.pop("payload")),
            {'user': {'username': username}},
        )
        self.assertEqual(
            serialized_event,
            {'id': str(m_uuid) + '_000003',
             'needles': ['_o:osquery_enrollment:19', '_p:18'],
             'serial_number': None,
             'tags': ['fomo', 'yolo', 'zentral'],
             'type': 'zentral_login'}
        )

    def test_event_serialization(self):
        self._test_serialization(serialize=False)

    def test_serialized_event_serialization(self):
        self._test_serialization(serialize=True)

    # event storage

    def test_store_not_available(self):
        store = self.get_store()
        event = build_login_event()
        with self.assertRaises(RuntimeError) as cm:
            list(store.store(event))
        self.assertEqual(cm.exception.args[0], "Only bulk_store is available")

    def test_bulk_store_not_available(self):
        store = self.get_store(batch_size=1)
        event = build_login_event()
        with self.assertRaises(RuntimeError) as cm:
            list(store.bulk_store([event]))
        self.assertEqual(cm.exception.args[0], "bulk_store is not available when batch_size < 2")

    def test_bulk_store_noop(self):
        store = self.get_store(batch_size=50)
        self.assertEqual(list(store.bulk_store([])), [])

    @patch("zentral.core.stores.backends.s3_parquet.S3ParquetStore._get_filesystem")
    def test_bulk_store(self, get_fs):
        get_fs.return_value = LocalFileSystem()
        prefix = get_random_string(12) + "/"
        store = self.get_store(bucket="/tmp", prefix=prefix, batch_size=50)
        store.wait_and_configure_if_necessary()
        filepath = store._get_parquet_path()
        store._fs.create_dir(os.path.dirname(filepath))
        event = build_login_event()
        self.assertEqual(
            list(store.bulk_store([event])),
            [(str(event.metadata.uuid), event.metadata.index)]
        )
        self.assertTrue(os.path.isfile(filepath))
        shutil.rmtree(os.path.join("/tmp", prefix))

    # serializer

    def test_serializer_missing_fields(self):
        s = S3ParquetStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"bucket": ["This field is required."],
             "region_name": ["This field is required."]},
        )

    def test_serializer_invalid_fields(self):
        s = S3ParquetStoreSerializer(data={
            "bucket": "",
            "region_name": "",
            "batch_size": 1234678,
            "max_batch_age_seconds": 12345678,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"bucket": ["This field may not be blank."],
             "region_name": ["This field may not be blank."],
             "batch_size": ["Ensure this value is less than or equal to 100000."],
             "max_batch_age_seconds": ["Ensure this value is less than or equal to 1200."]}
        )

    def test_serializer_role_with_key_error(self):
        s = S3ParquetStoreSerializer(data={
            "bucket": "yolo",
            "region_name": "eu-central-1",
            "aws_access_key_id": "fomo",
            "aws_secret_access_key": "omof",
            "assume_role_arn": "arn::role"
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"assume_role_arn": ["Cannot be used with an access key ID"]},
        )

    def test_serializer_defaults(self):
        s = S3ParquetStoreSerializer(data={
            "bucket": "123",
            "region_name": "us-central-1",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"bucket": "123",
             "prefix": "",
             "aws_access_key_id": None,
             "aws_secret_access_key": None,
             "assume_role_arn": None,
             "region_name": "us-central-1",
             "batch_size": 10000,
             "max_batch_age_seconds": 300},
        )

    def test_serializer_key_full(self):
        s = S3ParquetStoreSerializer(data={
            "bucket": "123",
            "prefix": "fomo/",
            "region_name": "us-central-1",
            "aws_access_key_id": "yolo",
            "aws_secret_access_key": "fomo",
            "batch_size": 100,
            "max_batch_age_seconds": 17,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"bucket": "123",
             "prefix": "fomo/",
             "region_name": "us-central-1",
             "aws_access_key_id": "yolo",
             "aws_secret_access_key": "fomo",
             "assume_role_arn": None,
             "batch_size": 100,
             "max_batch_age_seconds": 17},
        )

    def test_serializer_role_full(self):
        s = S3ParquetStoreSerializer(data={
            "bucket": "123",
            "prefix": "fomo/",
            "region_name": "us-central-1",
            "assume_role_arn": "arn::role",
            "batch_size": 100,
            "max_batch_age_seconds": 17,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"bucket": "123",
             "prefix": "fomo/",
             "region_name": "us-central-1",
             "aws_access_key_id": None,
             "aws_secret_access_key": None,
             "assume_role_arn": "arn::role",
             "batch_size": 100,
             "max_batch_age_seconds": 17},
        )

    # provisioning

    def test_provisioning(self):
        name = get_random_string(12).upper()
        s = StoreProvisioningSerializer(data={
            "name": name,
            "backend": "S3_PARQUET",
            "s3_parquet_kwargs": {
                "bucket": "bucket",
                "region_name": "eu-central-1",
            }
        })
        self.assertTrue(s.is_valid())
        db_store = s.save(provisioning_uid=get_random_string(12))
        self.assertEqual(db_store.slug, name.lower())
