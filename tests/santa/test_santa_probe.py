import json
import os.path
from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.contrib.santa.probes import SantaProbe
from zentral.contrib.santa.conf import build_santa_conf
from tests.inventory.utils import MockMetaMachine


def build_matching_santa_event(rule_type, sha256, decision, machine_serial_number=None):
    with open(os.path.join(os.path.dirname(__file__),
                           "fixtures/santa_event_allow_unknown_payload.json")) as f:
        payload = json.load(f)
    if rule_type == "BINARY":
        payload["file_sha256"] = sha256
    elif rule_type == "CERTIFICATE":
        payload["signing_chain"][0]["sha256"] = sha256
    payload["decision"] = decision
    SantaEvent = event_types["santa_event"]
    return SantaEvent(EventMetadata(machine_serial_number=machine_serial_number or "YO",
                                    event_type=SantaEvent.event_type),
                      payload)


class SantaProbeTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.binary_sha256 = ("b7839029302930293029392039203920"
                             "39203920392039203920392023232323")
        cls.certificate_sha256 = ("c7839029302930293029392039203920"
                                  "39203920392039203920392023232323")
        # blocklist
        cls.blocklist_rules = [{"policy": "BLACKLIST",
                                "rule_type": "BINARY",
                                "sha256": cls.binary_sha256},
                               {"policy": "BLACKLIST",
                                "rule_type": "CERTIFICATE",
                                "sha256": cls.certificate_sha256}]
        cls.probe_source_blocklist = ProbeSource.objects.create(
            model="SantaProbe",
            name="santa probe blocklist",
            status=ProbeSource.ACTIVE,
            body={"rules": cls.blocklist_rules}
        )
        cls.probe_blocklist = cls.probe_source_blocklist.load()
        # allowlist
        cls.allowlist_rules = [{"policy": "WHITELIST",
                                "rule_type": "BINARY",
                                "sha256": cls.binary_sha256},
                               {"policy": "WHITELIST",
                                "rule_type": "CERTIFICATE",
                                "sha256": cls.certificate_sha256}]
        cls.probe_source_allowlist = ProbeSource.objects.create(
            model="SantaProbe",
            name="santa probe allowlist",
            status=ProbeSource.ACTIVE,
            body={"rules": cls.allowlist_rules}
        )
        cls.probe_allowlist = cls.probe_source_allowlist.load()
        # tablet
        cls.tablet_rules = [{"policy": "BLACKLIST",
                             "rule_type": "BINARY",
                             "sha256": cls.binary_sha256[::-1]},
                            {"policy": "BLACKLIST",
                             "rule_type": "CERTIFICATE",
                             "sha256": cls.certificate_sha256[::-1]}]
        cls.probe_source_tablet = ProbeSource.objects.create(
            model="SantaProbe",
            name="santa probe machine",
            status=ProbeSource.ACTIVE,
            body={"filters": {"inventory": [{"types": ["TABLET"]}]},
                  "rules": cls.tablet_rules}
        )
        cls.probe_tablet = cls.probe_source_tablet.load()
        all_probes.clear()

    def test_probes(self):
        for probe in (self.probe_blocklist,
                      self.probe_allowlist,
                      self.probe_tablet):
            self.assertTrue(isinstance(probe, SantaProbe))

    def test_probes_metadata_filters(self):
        for probe in (self.probe_blocklist,
                      self.probe_allowlist,
                      self.probe_tablet):
            self.assertEqual(len(probe.metadata_filters), 1)
            metadata_filter = probe.metadata_filters[0]
            self.assertEqual(metadata_filter.event_types, set(["santa_event"]))
            self.assertEqual(metadata_filter.event_tags, set([]))

    def test_all_probes(self):
        santa_probes = list(all_probes.model_filter("SantaProbe"))
        self.assertEqual(len(santa_probes), 3)

    def test_probe_sources_event_type(self):
        for probe_source in (self.probe_source_blocklist,
                             self.probe_source_allowlist,
                             self.probe_source_tablet):
            self.assertEqual(probe_source.event_types, ["santa_event"])

    def test_probes_test_event(self):
        for rule_type, sha256, decision, bl_result, wl_result in (
                # wrong sha256
                ("BINARY", self.certificate_sha256, "ALLOW_BINARY", False, False),
                ("BINARY", self.certificate_sha256, "BLOCK_BINARY", False, False),
                ("CERTIFICATE", self.binary_sha256, "ALLOW_CERTIFICATE", False, False),
                ("CERTIFICATE", self.binary_sha256, "BLOCK_CERTIFICATE", False, False),
                # unknown decision
                ("BINARY", self.binary_sha256, "ALLOW_SCOPE", False, False),
                ("CERTIFICATE", self.certificate_sha256, "BLOCK_SCOPE", False, False),
                ("BINARY", self.binary_sha256, "ALLOW_UNKNOWN", False, False),
                ("CERTIFICATE", self.certificate_sha256, "BLOCK_UNKNOWN", False, False),
                # wrong decision
                ("BINARY", self.binary_sha256, "ALLOW_CERTIFICATE", False, False),
                ("BINARY", self.binary_sha256, "BLOCK_CERTIFICATE", False, False),
                ("CERTIFICATE", self.certificate_sha256, "ALLOW_BINARY", False, False),
                ("CERTIFICATE", self.certificate_sha256, "BLOCK_BINARY", False, False),
                # OK
                ("BINARY", self.binary_sha256, "ALLOW_BINARY", False, True),
                ("BINARY", self.binary_sha256, "BLOCK_BINARY", True, False),
                ("CERTIFICATE", self.certificate_sha256, "ALLOW_CERTIFICATE", False, True),
                ("CERTIFICATE", self.certificate_sha256, "BLOCK_CERTIFICATE", True, False)):
            event = build_matching_santa_event(rule_type, sha256, decision)
            self.assertEqual(self.probe_blocklist.test_event(event), bl_result)
            self.assertEqual(self.probe_allowlist.test_event(event), wl_result)
            # tablet
            sha256 = sha256[::-1]
            event = build_matching_santa_event(rule_type, sha256, decision)
            self.assertEqual(self.probe_tablet.test_event(event), False)
            # hack
            tablet = MockMetaMachine([], [], None, "TABLET")
            event.metadata.machine = tablet
            self.assertEqual(self.probe_tablet.test_event(event), bl_result)

    def test_santa_conf(self):
        def frozenrules(l):  # TODO: better ?
            return set(frozenset(r.items()) for r in l)

        # default machine has a subset of the rules
        default_machine = MockMetaMachine([], [], None, None)
        config = build_santa_conf(default_machine)
        self.assertEqual(len(config["rules"]), 4)
        self.assertEqual(frozenrules(config["rules"]),
                         frozenrules(self.blocklist_rules +
                                     self.allowlist_rules))

        # tablet has all the rules
        tablet = MockMetaMachine([], [], None, "TABLET")
        config = build_santa_conf(tablet)
        self.assertEqual(len(config["rules"]), 6)
        self.assertEqual(frozenrules(config["rules"]),
                         frozenrules(self.blocklist_rules +
                                     self.allowlist_rules +
                                     self.tablet_rules))
