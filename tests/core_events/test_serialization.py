from datetime import datetime
from django.core.cache import cache
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshotCommit
from zentral.core.events import event_from_event_d
from zentral.core.events.base import (BaseEvent,
                                      EventMetadata, EventRequest, EventRequestGeo, EventRequestUser,
                                      register_event_type)


class TestEvent3(BaseEvent):
    event_type = "event_type_3"


register_event_type(TestEvent3)


def make_event(ip=None, ua=None, with_msn=True, routing_key=None):
    msn = request = None
    if with_msn:
        msn = "0123456789"
    if ip or ua:
        request = EventRequest(user_agent=ua, ip=ip)
    else:
        request = None
    return TestEvent3(EventMetadata(machine_serial_number=msn,
                                    request=request,
                                    routing_key=routing_key,
                                    created_at=datetime(1990, 2, 11)),
                      {"godzilla": "yo"})


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class EventSerializationTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        source = {"module": "tests.zentral.io", "name": "Zentral Tests"}
        tree = {
            "source": source,
            "business_unit": {"name": "yo bu",
                              "reference": "bu1",
                              "source": source,
                              "links": [{"anchor_text": "bu link",
                                         "url": "http://bu-link.de"}]},
            "groups": [{"name": "yo grp",
                        "reference": "grp1",
                        "source": source,
                        "links": [{"anchor_text": "group link",
                                   "url": "http://group-link.de"}]}],
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
        }
        _, cls.ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)

    def test_event_without_msn(self):
        event = make_event(with_msn=False)
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertNotIn("machine_serial_number", metadata)
        self.assertNotIn("machine", metadata)

    def test_event_with_non_str_msn(self):
        for msn in ({"yolo": "fomo"}, ["yolo"], 123):
            with self.assertLogs("zentral.core.events.base", level="WARNING") as cm:
                metadata = EventMetadata(machine_serial_number=msn)
            self.assertIsNone(metadata.machine_serial_number)
            self.assertIsNone(metadata.machine)
            self.assertEqual(
                cm.output,
                [f"WARNING:zentral.core.events.base:Ignore machine serial number of type {type(msn).__name__}"]
            )

    def test_deserialized_event_with_non_str_msn(self):
        event_d = make_event(with_msn=False).serialize(machine_metadata=False)
        event_d["_zentral"]["machine_serial_number"] = ["yolo"]
        with self.assertLogs("zentral.core.events.base", level="WARNING"):
            event = event_from_event_d(event_d)
        metadata = event.serialize(machine_metadata=True)["_zentral"]
        self.assertNotIn("machine_serial_number", metadata)
        self.assertNotIn("machine", metadata)

    def test_event_with_msn_and_machine_metadata(self):
        event = make_event(with_msn=True)
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["machine_serial_number"], self.ms.serial_number)
        machine = metadata["machine"]
        self.assertEqual(machine["meta_business_units"][0]["id"],
                         self.ms.business_unit.meta_business_unit.pk)
        source_machine = machine["zentral-tests"]
        self.assertEqual(source_machine["groups"][0]["reference"], "grp1")
        self.assertEqual(source_machine["os_version"], "OS X 10.11.1")
        # cached info
        cache_key = f"mm-si_{self.ms.serial_number}"
        machine = cache.get(cache_key)
        self.assertEqual(machine["meta_business_units"][0]["id"],
                         self.ms.business_unit.meta_business_unit.pk)
        source_machine = machine["zentral-tests"]
        self.assertEqual(source_machine["groups"][0]["reference"], "grp1")
        self.assertEqual(source_machine["os_version"], "OS X 10.11.1")
        cache.delete(cache_key)

    def test_event_with_msn_without_machine_metadata(self):
        event = make_event(with_msn=True)
        d = event.serialize(machine_metadata=False)
        metadata = d["_zentral"]
        self.assertEqual(metadata["machine_serial_number"], self.ms.serial_number)
        self.assertNotIn("machine", metadata)
        event2 = TestEvent3.deserialize(d)
        self.assertEqual(event2.metadata.machine.serial_number, self.ms.serial_number)

    def test_event_with_request(self):
        event = make_event(ip="10.1.2.3")
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["request"], {"ip": "10.1.2.3"})
        event = make_event(ua="YO! ua")
        cache.delete(f"mm-si_{self.ms.serial_number}")
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertEqual(metadata["request"], {"user_agent": "YO! ua"})
        cache.delete(f"mm-si_{self.ms.serial_number}")

    def test_event_without_request(self):
        event = make_event()
        d = event.serialize()
        metadata = d["_zentral"]
        self.assertNotIn("request", metadata)
        cache.delete(f"mm-si_{self.ms.serial_number}")

    def test_event_routing_key(self):
        event = make_event(routing_key="yolo123")
        d = event.serialize(machine_metadata=False)
        self.assertEqual(d["_zentral"]["routing_key"], "yolo123")
        event2 = TestEvent3.deserialize(d)
        self.assertEqual(event2.metadata.routing_key, "yolo123")

    def test_event_request_deserialization(self):
        er = EventRequest.deserialize({
            'ip': '127.0.0.1',
            'method': 'GET',
            'path': '/',
            'geo': {
                'city_name': 'Hamburg',
                'continent_name': 'Europe',
                'country_iso_code': 'DE',
                'location': {'lat': 53.551086, 'lon': 9.993682},
                'region_name': 'Hamburg'
            },
            'user': {'email': 'godzilla@zentral.io',
                     'id': 17,
                     'is_remote': False,
                     'is_service_account': False,
                     'is_superuser': False,
                     'session': {'is_remote': False,
                                 'mfa_authenticated': False,
                                 'token': {'expiry': '1990-02-11T00:00:00',
                                           'name': 'token name',
                                           'pk': '00000000-0000-0000-0000-000000000001'},
                                 'token_authenticated': True},
                     'username': 'godzilla'}
        })
        self.assertIsInstance(er.geo, EventRequestGeo)
        self.assertIsInstance(er.user, EventRequestUser)
        self.assertEqual(er.geo.city_name, 'Hamburg')
        self.assertEqual(er.user.session["token"]["expiry"], datetime(1990, 2, 11))

    @staticmethod
    def _token_authenticated_user(expiry=datetime(1990, 2, 11), with_expiry=True):
        token = {"pk": "00000000-0000-0000-0000-000000000001", "name": "token name"}
        if with_expiry:
            token["expiry"] = expiry
        return EventRequestUser(
            id=17, username="godzilla", email="godzilla@zentral.io",
            is_remote=False, is_service_account=False, is_superuser=False,
            session={"token_authenticated": True, "is_remote": False,
                     "mfa_authenticated": False, "token": token},
        )

    def test_event_request_user_serialize_token_expiry(self):
        user = self._token_authenticated_user()
        d = user.serialize()
        self.assertEqual(d["session"]["token"]["expiry"], "1990-02-11T00:00:00")
        # the source session dict must not be mutated: it is shared by every
        # event built from a single request, so serialize() must leave the
        # datetime in place for the next event to serialize
        self.assertEqual(user.session["token"]["expiry"], datetime(1990, 2, 11))

    def test_event_request_user_serialize_is_idempotent(self):
        # a single request builds one EventRequest and shares it across every
        # event it emits (e.g. bulk machine tag changes); each event serializes
        # the same user, so a second serialize() must not raise or differ
        user = self._token_authenticated_user()
        first = user.serialize()
        second = user.serialize()
        self.assertEqual(first, second)
        self.assertEqual(second["session"]["token"]["expiry"], "1990-02-11T00:00:00")

    def test_event_request_user_serialize_token_without_expiry(self):
        user = self._token_authenticated_user(with_expiry=False)
        d = user.serialize()
        self.assertNotIn("expiry", d["session"]["token"])

    def test_event_request_user_serialize_session_without_token(self):
        user = EventRequestUser(
            id=17, username="godzilla", email="godzilla@zentral.io",
            is_remote=False, is_service_account=False, is_superuser=False,
            session={"token_authenticated": False, "is_remote": False, "mfa_authenticated": True},
        )
        d = user.serialize()
        self.assertNotIn("token", d["session"])
        self.assertEqual(d["session"]["mfa_authenticated"], True)
