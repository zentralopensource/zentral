from django.test import TestCase
from zentral.core.events import event_types
from zentral.core.events.base import EventMetadata
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


def build_munki_event(name, install_type, unattended, machine_tag_id, failed=False):
    event_type = f"munki_{install_type}"
    if failed:
        event_type += "_failed"
    event_cls = event_types[event_type]
    payload = payload_template.copy()
    payload["name"] = name
    payload["display_name"] = name.capitalize()
    payload["type"] = install_type
    payload["unattended"] = unattended
    event = event_cls(EventMetadata(machine_serial_number="YO"), payload)
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
        self.assertEqual(mf.event_types, set(["munki_install", "munki_install_failed"]))
        self.assertEqual(len(mf.event_tags), 0)

    def test_probe_source(self):
        ps, p = self.create_probe(install_types=["install"])
        self.assertEqual(set(ps.event_types), set(["munki_install", "munki_install_failed"]))

    def test_metadata_filters2(self):
        ps, p = self.create_probe(install_types=["removal", "install"])
        self.assertEqual(len(p.payload_filters), 0)
        self.assertEqual(set(ps.event_types), set(["munki_install", "munki_install_failed",
                                                   "munki_removal", "munki_removal_failed"]))

    def test_events_batch_1(self):
        ps, p = self.create_probe(install_types=["install"])
        tests = (
            ("Firefox", "removal", None, None, False, False),
            ("Firefox", "removal", None, None, True, False),
            ("Firefox", "install", None, None, False, True),
            ("Firefox", "install", True, None, False, True),
            ("Firefox", "install", False, None, False, True),
            ("Firefox", "install", False, None, True, True),
            ("Firefox", "install", None, 1, False, True),
        )
        for name, install_type, unattended, machine_tag_id, failed, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id, failed)
            self.assertEqual(p.test_event(event), result)

    def test_events_batch_2(self):
        ps, p = self.create_probe(install_types=["install"], machine_tag_id=1)
        tests = (
            ("Firefox", "install", None, None, False, False),
            ("Firefox", "install", None, None, True, False),
            ("Firefox", "install", None, 2, False, False),
            ("Firefox", "install", None, 2, True, False),
            ("Firefox", "install", None, 1, False, True),
            ("Firefox", "install", None, 1, True, True),
        )
        for name, install_type, unattended, machine_tag_id, failed, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id, failed)
            self.assertEqual(p.test_event(event), result)

    def test_events_batch_3(self):
        ps, p = self.create_probe(installed_item_names=["Firefox", "Chrome"],
                                  install_types=["removal"],
                                  unattended_installs=True)
        tests = (
            ("Firefox", "removal", None, None, False, False),
            ("Firefox", "removal", None, None, True, False),
            ("Firefox", "removal", False, None, False, False),
            ("Firefox", "removal", False, None, True, False),
            ("Firefox", "removal", True, None, False, True),
            ("Firefox", "removal", True, None, True, True),
            ("Firefox", "install", True, 2, False, False),
            ("Firefox", "install", True, 2, True, False),
            ("Chrome", "removal", True, 2, False, True),
            ("Chrome", "removal", True, 2, True, True),
            ("Yo", "removal", True, 2, False, False),
            ("Yo", "removal", True, 2, True, False),
        )
        for name, install_type, unattended, machine_tag_id, failed, result in tests:
            event = build_munki_event(name, install_type, unattended, machine_tag_id, failed)
            self.assertEqual(p.test_event(event), result)
