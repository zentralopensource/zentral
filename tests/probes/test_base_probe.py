from django.test import TestCase
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.core.events import event_types
from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.incidents.models import SEVERITY_CRITICAL
from zentral.core.probes.base import BaseProbe, get_flattened_payload_values
from zentral.core.probes.models import ProbeSource
from tests.inventory.utils import MockMetaMachine


class EmptyBaseProbeTestCase(TestCase):
    def setUp(self):
        self.probe_source = ProbeSource.objects.create(model="BaseProbe",
                                                       name="base probe",
                                                       body={})
        self.probe = self.probe_source.load()

    def test_slug(self):
        self.assertEqual(self.probe_source.slug, "base-probe")

    def test_inactive(self):
        self.assertEqual(self.probe_source.status, ProbeSource.INACTIVE)

    def test_empty_event_types(self):
        self.assertEqual(self.probe_source.event_types, [])

    def test_no_active_probe(self):
        self.assertEqual(ProbeSource.objects.active().count(), 0)

    def test_active(self):
        self.probe_source.status = ProbeSource.ACTIVE
        self.probe_source.save()
        self.assertEqual(ProbeSource.objects.active().count(), 1)

    def test_load(self):
        self.assertEqual(self.probe.loaded, True)
        self.assertTrue(isinstance(self.probe, BaseProbe))

    def test_empty(self):
        self.assertEqual(self.probe.inventory_filters, [])
        self.assertEqual(self.probe.metadata_filters, [])
        self.assertEqual(self.probe.payload_filters, [])
        self.assertEqual(self.probe.actions, [])
        self.assertEqual(self.probe.incident_severity, None)


class InventoryFilterBaseProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # test probe with an empty inventory filter
        # should not load and match
        cls.error_probe_source = ProbeSource.objects.create(
            status=ProbeSource.ACTIVE,
            model="BaseProbe",
            name="error probe",
            body={"filters": {"inventory": [{}]}}
        )
        cls.error_probe = cls.error_probe_source.load()
        # test probe
        cls.mbu1 = MetaBusinessUnit.objects.create(name="MBU1")
        cls.mbu2 = MetaBusinessUnit.objects.create(name="MBU2")
        cls.tag1 = Tag.objects.create(name="TAG1")
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name="base probe",
            body={"incident_severity": SEVERITY_CRITICAL,
                  "filters": {
                      "inventory": [
                          {"meta_business_unit_ids": [cls.mbu2.id,
                                                      cls.mbu1.id],
                           "tag_ids": [cls.tag1.id],
                           "platforms": ["WINDOWS", "MACOS", "LINUX"],
                           "types": ["TABLET", "LAPTOP"]},
                          {"types": ["VM"]}
                      ]
                  }}
        )
        cls.probe = cls.probe_source.load()

    def test_error_probe_not_loaded(self):
        self.assertEqual(self.error_probe.loaded, False)

    def test_error_probe_sourcce_inactive(self):
        self.assertEqual(self.error_probe_source.status, ProbeSource.INACTIVE)

    def test_incident_severity(self):
        self.assertEqual(self.probe.incident_severity, SEVERITY_CRITICAL)

    def test_inventory_filters(self):
        self.assertEqual(len(self.probe.inventory_filters), 2)

    def test_inventory_filter_meta_business_units(self):
        inventory_filter = self.probe.inventory_filters[0]
        self.assertEqual(inventory_filter.meta_business_unit_ids, set([self.mbu1.id, self.mbu2.id]))
        self.assertEqual(inventory_filter.meta_business_units, [self.mbu1, self.mbu2])  # ordering !

    def test_inventory_filter_tags(self):
        inventory_filter = self.probe.inventory_filters[0]
        self.assertEqual(inventory_filter.tag_ids, set([self.tag1.id]))
        self.assertEqual(inventory_filter.tags, [self.tag1])

    def test_inventory_filter_platforms(self):
        inventory_filter = self.probe.inventory_filters[0]
        self.assertEqual(inventory_filter.platforms, set(["WINDOWS", "MACOS", "LINUX"]))
        self.assertEqual(inventory_filter.get_platforms_display(), "Linux, macOS, Windows")  # ordering !

    def test_inventory_filter_types(self):
        inventory_filter = self.probe.inventory_filters[0]
        self.assertEqual(inventory_filter.types, set(["TABLET", "LAPTOP"]))
        self.assertEqual(inventory_filter.get_types_display(), "Laptop, Tablet")  # ordering !

    def test_inventory_filter_test_machine(self):
        inventory_filter = self.probe.inventory_filters[0]

        for mbuis, tis, p, t, result in (([], [], None, None, False),
                                         ([self.mbu1.id], [], "WINDOWS", "LAPTOP", False),
                                         ([self.mbu1.id], [12983719238], "WINDOWS", "LAPTOP", False),
                                         ([1238971298], [self.tag1.id], "WINDOWS", "LAPTOP", False),
                                         ([self.mbu1.id], [self.tag1.id], None, "LAPTOP", False),
                                         ([self.mbu1.id], [self.tag1.id], "WINDOWS", None, False),
                                         ([self.mbu1.id], [self.tag1.id], "WINDOWS", "LAPTOP", True)):
            mmm = MockMetaMachine(mbuis, tis, p, t)
            self.assertEqual(inventory_filter.test_machine(mmm), result)
            self.assertEqual(self.probe.test_machine(mmm), result)
            self.assertEqual(self.error_probe.test_machine(mmm), False)

    def test_probe_test_event(self):
        for mbuis, tis, p, t, result in (([1238971298], [self.tag1.id], "WINDOWS", "LAPTOP", False),
                                         ([self.mbu1.id], [self.tag1.id], "WINDOWS", "LAPTOP", True),
                                         ([self.mbu1.id], [self.tag1.id], "WINDOWS", "VM", True),
                                         ):
            event_metadata = EventMetadata(machine_serial_number="YO",
                                           event_type="base")
            # TODO hack
            event_metadata.machine = MockMetaMachine(mbuis, tis, p, t)
            event = BaseEvent(event_metadata, {"godzilla": "kommt"})
            self.assertEqual(self.probe.test_event(event), result)
            self.assertEqual(self.error_probe.test_event(event), False)


class MetadataFilterBaseProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.event_tags = ["osquery",
                          "inventory_update"]
        cls.event_types = ["inventory_reference_update",
                           "inventory_group_update"]
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name="base probe",
            body={"filters": {
                      "metadata": [
                          {"event_tags": cls.event_tags,
                           "event_types": cls.event_types},
                          {"event_types": ["osquery_result"]}
                       ]
                  }}
        )
        cls.probe = cls.probe_source.load()

    def test_probe_source_denormalization(self):
        self.assertEqual(self.probe_source.event_types,
                         sorted(self.event_types + ["osquery_result"]))

    def test_metadata_filters(self):
        self.assertEqual(len(self.probe.metadata_filters), 2)

    def test_metadata_filter_event_types(self):
        metadata_filter = self.probe.metadata_filters[0]
        self.assertEqual(metadata_filter.event_types,
                         set(self.event_types))
        self.assertEqual(metadata_filter.get_event_type_classes(),
                         [event_types[et] for et in sorted(self.event_types)])
        self.assertEqual(metadata_filter.get_event_types_display(),
                         "inventory group update, inventory reference update")

    def test_metadata_filter_event_tags(self):
        metadata_filter = self.probe.metadata_filters[0]
        self.assertEqual(metadata_filter.event_tags,
                         set(self.event_tags))
        self.assertEqual(metadata_filter.get_event_tags_display(),
                         "inventory update, osquery")

    def test_metadata_filter_test_event_metadata(self):
        metadata_filter = self.probe.metadata_filters[0]
        for event_type, tags, result in (("santa_event", ["yo"], False),
                                         ("inventory_group_update", ["yo"], False),
                                         ("santa_event", ["osquery"], False),
                                         ("inventory_group_update", [], False),
                                         ("inventory_group_update", ["osquery"], True),
                                         ("inventory_group_update", ["osquery", "yo"], True),
                                         ("inventory_reference_update", ["osquery", "inventory_update"], True)):
            metadata = EventMetadata(machine_serial_number="YO",
                                     event_type=event_type, tags=tags)
            self.assertEqual(metadata_filter.test_event_metadata(metadata),
                             result)

    def test_probe_test_event(self):
        for event_type, tags, result in (("santa_event", ["yo"], False),
                                         ("osquery_result", ["super", "michel"], True),
                                         ("inventory_group_update", ["osquery", "yo"], True)):
            event = BaseEvent(EventMetadata(machine_serial_number="YO",
                                            event_type=event_type, tags=tags),
                              {"godzilla": "kommt"})
            self.assertEqual(self.probe.test_event(event), result)


class PayloadFilterBaseProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.payload_filter_data = [
            {"attribute": "yo", "operator": "IN", "values": ["yoval2", "yoval1"]},
            {"attribute": "yo2", "operator": "IN", "values": ["yo2val"]},
        ]
        cls.payload_filter_data2 = [
            {"attribute": "zo", "operator": "IN", "values": ["zoval2", "zoval1"]},
            {"attribute": "zo2", "operator": "IN", "values": ["zo2val"]},
        ]
        cls.payload_filter_data3 = [
            {"attribute": "a.b.c", "operator": "IN", "values": ["abc"]}
        ]
        cls.payload_filter_data4 = [
            {"attribute": "yo", "operator": "NOT_IN", "values": ["notin23"]},
            {"attribute": "ewuew", "operator": "IN", "values": ["z99", "a00"]},
        ]
        cls.payload_filter_data5 = [
            {"attribute": "yo_bool", "operator": "IN", "values": ["True"]},
        ]
        cls.payload_filter_data6 = [
            {"attribute": "yo_int", "operator": "IN", "values": ["42"]},
        ]
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name="base probe",
            body={"filters": {"payload": [cls.payload_filter_data,
                                          cls.payload_filter_data2,
                                          cls.payload_filter_data3,
                                          cls.payload_filter_data4,
                                          cls.payload_filter_data5,
                                          cls.payload_filter_data6]}}
        )
        cls.probe = cls.probe_source.load()

    def test_payload_filters(self):
        self.assertEqual(len(self.probe.payload_filters), 6)

    def test_payload_filter_items(self):
        payload_filter = self.probe.payload_filters[3]
        self.assertEqual(payload_filter.items,
                         sorted([(d["attribute"], d["operator"], set(d["values"]))
                                 for d in self.payload_filter_data4]))
        self.assertEqual(payload_filter.items_display(),
                         [("ewuew", "=", ["a00", "z99"]),
                          ("yo", "!=", ["notin23"])])

    def test_payload_filter_test_event_payload(self):
        payload_filter = self.probe.payload_filters[0]
        for payload, result in (({}, False),
                                ({"un": 1}, False),
                                ({"yo": "yoval1"}, False),
                                ({"yo": "yoval1", "yo3": [1, 2]}, False),
                                ({"yo": "yoval1", "yo2": ["yo2val"]}, True),
                                ({"yo": "notin23", "zo2": ["yo2val"]}, False),
                                ({"yo": ["yoval1", "yoval2", "yoval3"], "yo2": "yo2val"}, True),
                                ({"yo": ["yoval1", "yoval2", "yoval3"], "yo2": "yo2val"}, True),
                                ):
            self.assertEqual(payload_filter.test_event_payload(payload),
                             result)

    def test_payload_filter_test_event_not_in_payload(self):
        payload_filter = self.probe.payload_filters[3]
        for payload, result in (({}, False),
                                ({"yoloooooo": 1}, False),
                                ({"ewuew": 1}, False),
                                ({"ewuew": "z99"}, True),
                                ({"yo": "notin23"}, False),
                                ({"yo": "notin23", "ewuew": ["z99"]}, False),
                                ({"yo": "yoval1", "ewuew": ["z99"]}, True),
                                ):
            self.assertEqual(payload_filter.test_event_payload(payload),
                             result)

    def test_payload_filter_test_event_boolean_in_payload(self):
        payload_filter = self.probe.payload_filters[4]
        for payload, result in (({}, False),
                                ({"yo_bool": 1}, False),
                                ({"yo_bool": "False"}, False),
                                ({"yo_bool": "dlekjde delkjd qeldkj"}, False),
                                ({"yo_bool": False}, False),
                                ({"yo_bool": "True"}, True),
                                ({"yo_bool": True}, True),
                                ):
            self.assertEqual(payload_filter.test_event_payload(payload),
                             result)

    def test_payload_filter_test_event_integer_in_payload(self):
        payload_filter = self.probe.payload_filters[5]
        for payload, result in (({}, False),
                                ({"yo_int": "yolo"}, False),
                                ({"yo_int": True}, False),
                                ({"yo_int": 33}, False),
                                ({"yo_int": 42}, True),
                                ):
            self.assertEqual(payload_filter.test_event_payload(payload),
                             result)

    def test_get_flattened_payload_values(self):
        for payload, attrs, result in (({"a": 1}, ["a"], {"1"}),
                                       ({"a": [{"b": [2, 3, 3]}]}, ["a", "b"], {"2", "3"})):
            self.assertEqual(set(get_flattened_payload_values(payload, attrs)), result)

    def test_dotted_payload_attribute(self):
        payload_filter = self.probe.payload_filters[2]
        for payload, result in (({"a": 1}, False),
                                ({"a": {"b": {"d": "d"}}}, False),
                                ({"a": {"b": {"c": "ab", "d": "d"}}}, False),
                                ({"a": {"b": {"c": set(["abc"]), "d": "d"}}}, True),
                                ({"a": {"b": [{"c": set(["abc"]), "d": "d"}]}}, True),
                                ({"a": [{"b": [{"d": "u"},
                                               {"c": "abc", "d": "d"}]}]}, True),
                                ):
            self.assertEqual(payload_filter.test_event_payload(payload),
                             result)

    def test_probe_test_event(self):
        for payload, result in (({}, False),
                                ({"un": 1}, False),
                                ({"yo": "yoval1", "yo2": ["yo2val"]}, True),
                                ({"zo": "zoval1", "zo2": ["zo2val"]}, True),
                                ({"yo": "yoval1", "zo2": ["zo2val"]}, False),
                                ({"yo": "notin23", "zo2": ["yo2val"]}, False),
                                ({"a": 1}, False),
                                ({"a": {"b": {"c": "abc", "d": "d"}}}, True),
                                ({"a": [{"b": {"c": "abc", "d": "d"}}]}, True),
                                ({"a": [{"b": [{"c": "abc", "d": "d"}]}]}, True),
                                ):
            event = BaseEvent(EventMetadata(machine_serial_number="YOZO",
                                            event_type=BaseEvent.event_type),
                              payload)
            self.assertEqual(self.probe.test_event(event), result)
