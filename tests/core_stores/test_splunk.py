import datetime
from unittest.mock import call, patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from zentral.core.stores.backends.all import StoreBackend
from zentral.core.stores.backends.splunk import SplunkStore, SplunkStoreSerializer
from .utils import build_login_event, force_store


class TestSplunkStore(TestCase):
    maxDiff = None

    def get_store(self, **kwargs):
        for arg, default in (("hec_url", "https://www.example.com/hec/"),
                             ("hec_token", "hec_token"),
                             ("hec_extra_headers", [{"name": "X-Yolo", "value": "Fomo"}]),
                             ("hec_request_timeout", 120),
                             ("hec_index", "Zentral"),
                             ("hec_source", "zentral"),
                             ("computer_name_as_host_sources", ["munki", "osquery"]),
                             ("custom_host_field", "custom_host"),
                             ("serial_number_field", "serial_number"),
                             ("batch_size", 17),
                             ("search_app_url", "https://www.example.com/search_app/"),
                             ("search_url", "https://www.example.com/search/"),
                             ("search_token", "search_token"),
                             ("search_extra_headers", [{"name": "X-Yolo", "value": "Fomo"}]),
                             ("search_request_timeout", 30),
                             ("search_index", "Zentral"),
                             ("search_source", "zentral"),
                             ("verify_tls", True)):
            if arg not in kwargs:
                kwargs[arg] = default
        return force_store(backend=StoreBackend.Splunk, backend_kwargs=kwargs)

    # backend model

    def test_backend_get_backend(self):
        store = self.get_store()
        self.assertIsInstance(store, SplunkStore)
        store2 = store.instance.get_backend(load=True)
        self.assertIsInstance(store2, SplunkStore)
        self.assertEqual(store2.instance, store.instance)

    def test_backend_encrypted_kwargs(self):
        store = self.get_store()
        self.assertEqual(
            store.instance.backend_kwargs,
            {'batch_size': 17,
             'computer_name_as_host_sources': ['munki', 'osquery'],
             'custom_host_field': 'custom_host',
             'hec_extra_headers': [{'name': 'X-Yolo', 'value': 'noop$Rm9tbw=='}],  # "encrypted"
             'hec_index': 'Zentral',
             'hec_request_timeout': 120,
             'hec_source': 'zentral',
             'hec_token': 'noop$aGVjX3Rva2Vu',  # "encrypted"
             'hec_url': 'https://www.example.com/hec/',
             'search_app_url': 'https://www.example.com/search_app/',
             'search_extra_headers': [{'name': 'X-Yolo', 'value': 'noop$Rm9tbw=='}],  # "encrypted"
             'search_request_timeout': 30,
             'search_index': 'Zentral',
             'search_source': 'zentral',
             'search_token': 'noop$c2VhcmNoX3Rva2Vu',  # "encrypted"
             'search_url': 'https://www.example.com/search/',
             'serial_number_field': 'serial_number',
             'verify_tls': True}
        )

    def test_backend_serialize_for_event(self):
        store = self.get_store()
        store.instance.provisioning_uid = get_random_string(12)
        store.instance.save()
        role = Group.objects.create(name=get_random_string(12))
        store.instance.events_url_authorized_roles.add(role)
        self.assertEqual(
            store.instance.serialize_for_event(),
            {'admin_console': False,
             'backend': 'SPLUNK',
             'backend_kwargs': {
                 'batch_size': 17,
                 'computer_name_as_host_sources': ['munki', 'osquery'],
                 'custom_host_field': 'custom_host',
                 'hec_extra_headers': [
                     {'name': 'X-Yolo',
                      'value_hash': '23abd07bdc188e0aec2bffd0f1bd0cd130df9a53e68668c467463d55c705e53a'}
                 ],
                 'hec_index': 'Zentral',
                 'hec_request_timeout': 120,
                 'hec_source': 'zentral',
                 'hec_token_hash': '0f4ea96f035a1454218850b1592c47f7ea5f4d337386c74d5f747225d4ba721f',
                 'hec_url': 'https://www.example.com/hec/',
                 'search_app_url': 'https://www.example.com/search_app/',
                 'search_extra_headers': [
                     {'name': 'X-Yolo',
                      'value_hash': '23abd07bdc188e0aec2bffd0f1bd0cd130df9a53e68668c467463d55c705e53a'}
                 ],
                 'search_request_timeout': 30,
                 'search_index': 'Zentral',
                 'search_source': 'zentral',
                 'search_token_hash': 'd0cce61f474179c3a4e453fc19f3cd2ef9979bc8272aa3c1ffa4e4f6f4d26a74',
                 'search_url': 'https://www.example.com/search/',
                 'serial_number_field': 'serial_number',
                 'verify_tls': True
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

    def test_search_app_url_absent(self):
        store = self.get_store(search_app_url=None)
        for attr in ("machine_events_url", "object_events_url", "probe_events_url"):
            self.assertFalse(getattr(store, attr))

    def test_search_app_url_present(self):
        store = self.get_store(search_app_url="https://www.example.com/search/")
        for attr in ("machine_events_url", "object_events_url", "probe_events_url"):
            self.assertTrue(getattr(store, attr))

    def test_search_token_absent(self):
        store = self.get_store(search_token=None)
        for attr in ("last_machine_heartbeats", "machine_events", "object_events", "probe_events"):
            self.assertFalse(getattr(store, attr))

    def test_search_token_present(self):
        store = self.get_store(search_token="123")
        for attr in ("last_machine_heartbeats", "machine_events", "object_events", "probe_events"):
            self.assertTrue(getattr(store, attr))

    @patch("zentral.core.stores.backends.splunk.logger")
    def test_hec_session(self, logger):
        store = self.get_store(
            hec_url="https://splunk.example.com:8088/services/collector/event",
            hec_token=get_random_string(12),
            hec_request_timeout=17,
            hec_extra_headers=[
                {"name": "X-YOLO", "value": "FOMO"},  # OK header
                {"name": "Authorization", "value": "yolo"},  # Must be skipped
                {"name": "Content-Type", "value": "fomo"},  # Must be skipped
            ]
        )
        session = store.hec_session
        logger.debug.assert_has_calls(
            [call("Set '%s' %s extra header", "X-YOLO", "https://splunk.example.com:8088/services/collector/event")]
        )
        logger.error.assert_has_calls(
            [call("Skip '%s' %s extra header",
                  "Authorization", "https://splunk.example.com:8088/services/collector/event"),
             call("Skip '%s' %s extra header",
                  "Content-Type", "https://splunk.example.com:8088/services/collector/event")],
            any_order=True,
        )
        self.assertEqual(session.headers["X-YOLO"], "FOMO")
        self.assertTrue(session is store.hec_session)  # cached property

    # event serialization

    def test_event_id_serialization(self):
        event = build_login_event()
        store = self.get_store()
        serialized_event = store._serialize_event(event)
        self.assertEqual(serialized_event["event"]["id"], f"{str(event.metadata.uuid)}:{event.metadata.index}")
        self.assertNotIn("index", serialized_event["event"])

    def test_serialized_event_id_serialization(self):
        event = build_login_event()
        store = self.get_store()
        serialized_event = store._serialize_event(event.serialize())
        self.assertEqual(serialized_event["event"]["id"], f"{str(event.metadata.uuid)}:{event.metadata.index}")
        self.assertNotIn("index", serialized_event["event"])

    def test_event_id_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9:17", '
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        store = self.get_store()
        event = store._deserialize_event(serialized_event)
        self.assertEqual(event.event_type, "zentral_login")
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))
        self.assertEqual(event.metadata.index, 17)
        self.assertEqual(event.metadata.namespace, "zentral")
        self.assertEqual(event.payload["user"], {"username": "YONpsAgaKguu"})

    def test_legacy_event_id_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9", "index": 42,'
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        store = self.get_store()
        event = store._deserialize_event(serialized_event)
        self.assertEqual(event.event_type, "zentral_login")
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))
        self.assertEqual(event.metadata.index, 42)
        self.assertEqual(event.metadata.namespace, "zentral")
        self.assertEqual(event.payload["user"], {"username": "YONpsAgaKguu"})

    def test_custom_host_field_serialization(self):
        event = build_login_event()
        store = self.get_store(custom_host_field="computername")
        serialized_event = store._serialize_event(event)
        self.assertEqual(serialized_event["event"]["computername"], "Zentral")

    def test_custom_host_field_deserialization(self):
        serialized_event = {
            "_raw": '{"id": "f83b54ef-d3de-42c9-ae61-76669dcac0a9:17", '
                    '"namespace": "zentral", "tags": ["zentral"], '
                    '"computername": "Zentral", '
                    '"zentral": {"user": {"username": "YONpsAgaKguu"}}}',
            "_time": "2010-07-18T19:19:30.000+00:00",
            "sourcetype": "zentral_login",
        }
        store = self.get_store(custom_host_field="computername")
        event = store._deserialize_event(serialized_event)
        self.assertEqual(event.metadata.uuid, uuid.UUID("f83b54ef-d3de-42c9-ae61-76669dcac0a9"))

    # event storage

    @patch("zentral.core.stores.backends.splunk.SplunkStore.hec_session")
    def test_store_event_error_no_retry(self, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 400
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        event = build_login_event()
        store = self.get_store(batch_size=1, hec_request_timeout=123)
        with self.assertRaises(Exception) as cm:
            store.store(event)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 1)
        self.assertEqual(hec_session.post.call_args_list[0].args[0], "https://www.example.com/hec/")
        self.assertEqual(hec_session.post.call_args_list[0].kwargs["timeout"], 123)

    @patch("zentral.core.stores.backends.splunk.SplunkStore.hec_session")
    def test_bulk_store_events_error_no_retry(self, hec_session):
        response = Mock()
        response.ok = False
        response.status_code = 400
        response.raise_for_status.side_effect = Exception("BOOM!")
        hec_session.post.return_value = response
        events = [build_login_event(), build_login_event()]
        store = self.get_store(batch_size=17, hec_request_timeout=123)
        with self.assertRaises(Exception) as cm:
            store.bulk_store(events)
        self.assertEqual(cm.exception.args[0], "BOOM!")
        self.assertEqual(len(hec_session.post.call_args_list), 1)
        self.assertEqual(hec_session.post.call_args_list[0].args[0], "https://www.example.com/hec/")
        self.assertEqual(hec_session.post.call_args_list[0].kwargs["timeout"], 123)

    # events URLs

    def test_get_machine_events_url(self):
        store = self.get_store()
        self.assertEqual(
            store.get_machine_events_url(
                "012345678910",
                datetime.datetime(2025, 7, 13),
                to_dt=datetime.datetime(2027, 7, 12),
                event_type="zentral_login"
            ),
            "https://www.example.com/search_app/?q=search+index%3D%22Zentral%22+source%3D%22zentral"
            "%22+sourcetype%3D%22zentral_login%22+serial_number%3D%22012345678910%22"
            "&earliest=1752364800.000&latest=1815350400.000"
        )

    # serializer

    def test_serializer_missing_fields(self):
        s = SplunkStoreSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"hec_url": ["This field is required."],
             "hec_token": ["This field is required."]}
        )

    def test_serializer_invalid_fields(self):
        s = SplunkStoreSerializer(data={
            "hec_url": "https://",
            "hec_token": "",
            "hec_extra_headers": [{"name": "Authorization", "value": "Bearer yolo"}],
            "hec_request_timeout": 0,
            "computer_name_as_host_sources": [""],
            "batch_size": 1234,
            "search_app_url": "https://",
            "search_url": "https://",
            "search_token": "",
            "search_extra_headers": [{"name": "Content-Type", "value": "text/html"}],
            "search_request_timeout": 0,
        })
        self.assertFalse(s.is_valid())
        self.assertEqual(
            s.errors,
            {"hec_url": ["Invalid URL netloc"],
             "hec_token": ["This field may not be blank."],
             "hec_extra_headers": ["Authorization and Content-Type headers cannot be changed"],
             "hec_request_timeout": ["Ensure this value is greater than or equal to 1."],
             "computer_name_as_host_sources": {0: ["This field may not be blank."]},
             "batch_size": ["Ensure this value is less than or equal to 100."],
             "search_app_url": ["Invalid URL netloc"],
             "search_url": ["Invalid URL netloc"],
             "search_token": ["This field may not be blank."],
             "search_extra_headers": ["Authorization and Content-Type headers cannot be changed"],
             "search_request_timeout": ["Ensure this value is greater than or equal to 1."]}
        )

    def test_serializer_defaults(self):
        s = SplunkStoreSerializer(data={
            "hec_url": "https://www.example.com/hec",
            "hec_token": "yolo",
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"hec_url": "https://www.example.com/hec",
             "hec_token": "yolo",
             "hec_request_timeout": 300,
             "hec_index": None,
             "hec_source": None,
             "custom_host_field": None,
             "serial_number_field": "machine_serial_number",
             "batch_size": 1,
             "search_app_url": None,
             "search_url": None,
             "search_token": None,
             "search_index": None,
             "search_source": None,
             "search_request_timeout": 300,
             "verify_tls": True}
        )

    def test_serializer_full(self):
        s = SplunkStoreSerializer(data={
            "hec_url": "https://www.example.com/hec",
            "hec_token": "hec_token",
            "hec_extra_headers": [{"name": "X-HEC-Yolo", "value": "Fomo"}],
            "hec_request_timeout": 123,
            "hec_index": "HECIndex",
            "hec_source": "HECSource",
            "computer_name_as_host_sources": ["munki", "osquery"],
            "custom_host_field": "my_host",
            "serial_number_field": "serial_number",
            "batch_size": 50,
            "search_app_url": "https://www.example.com/search_app",
            "search_url": "https://www.example.com/search",
            "search_token": "search_token",
            "search_extra_headers": [{"name": "X-Search-Yolo", "value": "Fomo"}],
            "search_request_timeout": 456,
            "search_index": "SearchIndex",
            "search_source": "SearchSource",
            "verify_tls": False,
        })
        self.assertTrue(s.is_valid())
        self.assertEqual(
            s.data,
            {"hec_url": "https://www.example.com/hec",
             "hec_token": "hec_token",
             "hec_extra_headers": [{"name": "X-HEC-Yolo", "value": "Fomo"}],
             "hec_request_timeout": 123,
             "hec_index": "HECIndex",
             "hec_source": "HECSource",
             "computer_name_as_host_sources": ["munki", "osquery"],
             "custom_host_field": "my_host",
             "serial_number_field": "serial_number",
             "batch_size": 50,
             "search_app_url": "https://www.example.com/search_app",
             "search_url": "https://www.example.com/search",
             "search_token": "search_token",
             "search_extra_headers": [{"name": "X-Search-Yolo", "value": "Fomo"}],
             "search_request_timeout": 456,
             "search_index": "SearchIndex",
             "search_source": "SearchSource",
             "verify_tls": False}
        )
