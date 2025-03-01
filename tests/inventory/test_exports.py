import csv
import json
import zipfile
from django.core.files.storage import default_storage
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshotCommit
from zentral.contrib.inventory.utils import (do_full_export,
                                             export_machine_macos_app_instances,
                                             export_machine_snapshots)


class InventoryExportsTests(TestCase):
    # utils

    def commit_machine_snapshot(self, serial_number=None):
        if serial_number is None:
            serial_number = get_random_string(12)
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
            "serial_number": serial_number,
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"},
            ],
            "extra_facts": {"un": 1, "deux": "zwei"}
        }
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        return serial_number

    def test_full_export(self):
        serial_number = self.commit_machine_snapshot()
        result = do_full_export()
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                self.assertEqual(
                    sorted(zf.namelist()),
                    ['zentral_business_unit_0001.jsonl',
                     'zentral_machine_0001.jsonl',
                     'zentral_machine_macos_app_instance_0001.jsonl',
                     'zentral_macos_app_0001.jsonl',
                     'zentral_macos_app_instance_0001.jsonl',
                     'zentral_meta_business_unit_0001.jsonl',
                     'zentral_os_version_0001.jsonl',
                     'zentral_source_0001.jsonl']
                )
                with zf.open("zentral_machine_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    machine_d = json.loads(content[0])
                    self.assertEqual(machine_d["serial_number"], serial_number)
        default_storage.delete(result["filepath"])

    def test_export_machine_snapshots(self):
        serial_number = self.commit_machine_snapshot()
        result = export_machine_snapshots(source_name="ZENTRAL TESTS")
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                filename = zf.namelist()[0]
                self.assertEqual(filename, "zentral-tests.jsonl")
                with zf.open(filename) as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    snapshot = json.loads(content[0])
                    self.assertEqual(snapshot["serial_number"], serial_number)
                    self.assertEqual(snapshot["os_version"], {'major': 10, 'minor': 11, 'name': 'OS X', 'patch': 1})
                    self.assertEqual(snapshot["extra_facts"], {"un": 1, "deux": "zwei"})
        default_storage.delete(result["filepath"])

    def test_export_machine_macos_app_instances(self):
        serial_number = self.commit_machine_snapshot()
        result = export_machine_macos_app_instances(source_name="ZENTRAL TESTS")
        headers = None
        with default_storage.open(result["filepath"]) as f:
            path = zipfile.Path(f, at="zentral-tests.csv")
            csv_f = path.open(newline='')
            reader = csv.reader(csv_f)
            for row in reader:
                if headers is None:
                    headers = row
                else:
                    row = dict(zip(headers, row))
            row.pop("last_seen")
            self.assertEqual(
                row,
                {'bundle_display_name': '',
                 'bundle_id': 'io.zentral.baller',
                 'bundle_name': 'Baller.app',
                 'bundle_path': '/Applications/Baller.app',
                 'bundle_version': '123',
                 'bundle_version_str': '1.2.3',
                 'path': '',
                 'serial_number': serial_number,
                 'source_module': 'tests.zentral.io',
                 'source_name': 'Zentral Tests'}
            )
        default_storage.delete(result["filepath"])
