from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
from zentral.core.probes.base import PayloadFilter
from zentral.core.probes.models import ProbeSource
from tests.inventory.utils import MockMetaMachine


payload_template = {
    "unattended": True,
    "run_type": "auto",
    "status": 0,
    "duration_seconds": 16,
    "basename": "ManagedInstallReport.plist",
    "type": "install",
    "applesus": False,
    "munki_version": "2.8.0.2810",
    "version": "50.0",
    "display_name": "Mozilla Firefox",
    "sha1sum": "8d08cb494d4a8ee11678d7734ea5ddb6aef50dad",
    "download_kbytes_per_sec": 10513
}


def build_munki_event(name, install_type, unattended, machine_tag_id):
    MunkiEvent = event_types["munki_event"]
    payload = payload_template.copy()
    payload["name"] = name
    payload["display_name"] = name.capitalize()
    payload["type"] = install_type
    payload["unattended"] = unattended
    event = MunkiEvent(EventMetadata(machine_serial_number="YO",
                                     event_type=MunkiEvent.event_type),
                       payload)
    if machine_tag_id:
        # hack
        event.metadata.machine = MockMetaMachine([], [machine_tag_id], None, None, serial_number="YO")
    return event


class MunkiInstallProbeTestCase(TestCase):
    def create_probe(self, install_types, installed_item_names=None, unattended_installs=None, machine_tag_id=None):
        body = {"install_types": install_types}
        if installed_item_names:
            body["installed_item_names"] = installed_item_names
        if unattended_installs is not None:
            body["unattended_installs"] = unattended_installs
        if machine_tag_id:
            body["filters"] = {"inventory": [{"tag_ids": [machine_tag_id]}]}
        ps = ProbeSource.objects.create(
            model="MunkiInstallProbe",
            name="munki install probe",
            body=body
        )
        p = ps.load()
        return ps, p

    def test_metadata_filters(self):
        ps, p = self.create_probe(install_types=["install"])
        self.assertEqual(len(p.metadata_filters), 1)
        mf = p.metadata_filters[0]
        self.assertEqual(mf.event_types, set(["munki_event"]))
        self.assertEqual(len(mf.event_tags), 0)

    def test_probe_source(self):
        ps, p = self.create_probe(install_types=["install"])
        self.assertEqual(ps.event_types, ["munki_event"])

    def test_payload_filters(self):
        ps, p = self.create_probe(install_types=["removal", "install"])
        self.assertEqual(len(p.payload_filters), 1)
        pf = p.payload_filters[0]
        self.assertEqual(len(pf.items), 1)
        self.assertEqual(pf.items[0], ("type", PayloadFilter.IN, set(["removal", "install"])))

    def test_events_batch_1(self):
        ps, p = self.create_probe(install_types=["install"])
        tests = (
            ("Firefox", "removal", None, None, False),
            ("Firefox", "install", None, None, True),
            ("Firefox", "install", True, None, True),
            ("Firefox", "install", False, None, True),
            ("Firefox", "install", None, 1, True),
        )
        for name, install_type, unattended, machine_tag_id, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id)
            self.assertEqual(p.test_event(event), result)

    def test_events_batch_2(self):
        ps, p = self.create_probe(install_types=["install"], machine_tag_id=1)
        tests = (
            ("Firefox", "install", None, None, False),
            ("Firefox", "install", None, 2, False),
            ("Firefox", "install", None, 1, True),
        )
        for name, install_type, unattended, machine_tag_id, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id)
            self.assertEqual(p.test_event(event), result)

    def test_events_batch_3(self):
        ps, p = self.create_probe(installed_item_names=["Firefox", "Chrome"],
                                  install_types=["removal"],
                                  unattended_installs=True)
        tests = (
            ("Firefox", "removal", None, None, False),
            ("Firefox", "removal", False, None, False),
            ("Firefox", "removal", True, None, True),
            ("Firefox", "install", True, 2, False),
            ("Chrome", "removal", True, 2, True),
            ("Yo", "removal", True, 2, False),
        )
        for name, install_type, unattended, machine_tag_id, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id)
            self.assertEqual(p.test_event(event), result)
