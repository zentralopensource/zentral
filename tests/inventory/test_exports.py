import csv
from datetime import datetime
import hashlib
import json
import zipfile
from django.core.files.storage import default_storage
from django.test import TestCase, TransactionTestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshot, MachineSnapshotCommit, MetaBusinessUnit, Source
from zentral.contrib.inventory.utils import (do_full_export,
                                             export_machine_macos_app_instances,
                                             export_machine_snapshots)
from zentral.contrib.inventory.utils.full_export import FULL_EXPORT_QUERIES, export_transaction


# The *_id columns of the export that the naming rule (<table>_id → <table>.id) does not resolve, with the reason.
NOT_FOREIGN_KEYS = {
    ("ec2_instance_metadata", "account_id"): "an AWS account ID",
    ("ec2_instance_metadata", "ami_id"): "an AMI ID",
    ("ec2_instance_metadata", "instance_id"): "an EC2 instance ID",
    ("ec2_instance_metadata", "reservation_id"): "an EC2 reservation ID",
    ("macos_app", "bundle_id"): "a bundle identifier",
    ("macos_app_instance", "team_id"): "an Apple team ID",
    ("principal_user", "unique_id"): "the identifier of the user at its source",
}
RENAMED_FOREIGN_KEYS = {
    ("certificate", "signed_by_id"): "certificate",
    ("macos_app_instance", "signed_by_id"): "certificate",
    ("profile", "signed_by_id"): "certificate",
}
NOT_EXPORTED_TARGETS = {
    ("principal_user", "source_id"): "inventory_principalusersource is not exported",
}


def sha_256(*parts):
    return hashlib.sha256(" ".join(parts).encode("utf-8")).hexdigest()


def root_certificate():
    return {"common_name": "Apple Root CA", "sha_256": sha_256("root")}


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
                 'bundle_path': "/Applications/Baller.app",
                 'executable_path': "/Applications/Baller_path",
                 'team_id': "ABCDE12345",
                 'cd_hash': "0123456789abcdef0123456789abcdef01234567",
                 'entitlements': {"com.apple.security.app-sandbox": True,
                                  "com.apple.security.network.client": True},
                 'signing_time': datetime(2024, 1, 2, 3, 4, 5),
                 'secure_signing_time': datetime(2024, 1, 2, 3, 4, 6)},
            ],
            "disks": [
                {"name": "/dev/disk3s1s1",
                 "size": 62826479616,
                 "encryption_status": "encrypted",
                 "filevault_status": "on",
                 "label": "com.apple.os.update-C6AB179000F92C4C211177BC5C840A511D1AA2A227C324AA9AAC14FC599E9873",
                 "path": "/"},
            ],
            "network_interfaces": [
                {"interface": "en0",
                 "mac": "b0:be:00:00:00:00",
                 "address": "192.168.1.18",
                 "mask": "255.255.255.0",
                 "broadcast": "192.168.1.255"}
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
                     'zentral_disk_0001.jsonl',
                     'zentral_machine_0001.jsonl',
                     'zentral_machine_disks_0001.jsonl',
                     'zentral_machine_macos_app_instance_0001.jsonl',
                     'zentral_machine_network_interface_0001.jsonl',
                     'zentral_macos_app_0001.jsonl',
                     'zentral_macos_app_instance_0001.jsonl',
                     'zentral_meta_business_unit_0001.jsonl',
                     'zentral_network_interface_0001.jsonl',
                     'zentral_os_version_0001.jsonl',
                     'zentral_source_0001.jsonl']
                )
                with zf.open("zentral_machine_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    machine_d = json.loads(content[0])
                    self.assertEqual(machine_d["serial_number"], serial_number)
                    ms_id = machine_d["ms_id"]
                with zf.open("zentral_disk_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    disk_d = json.loads(content[0])
                    self.assertEqual(disk_d["filevault_status"], "on")
                    d_id = disk_d["id"]
                with zf.open("zentral_machine_disks_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    mdi_d = json.loads(content[0])
                    self.assertEqual(mdi_d, {"ms_id": ms_id, "disk_id": d_id})
                with zf.open("zentral_network_interface_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    network_interface_d = json.loads(content[0])
                    self.assertEqual(network_interface_d["mac"], "b0:be:00:00:00:00")
                    ni_id = network_interface_d["id"]
                with zf.open("zentral_machine_network_interface_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    mni_d = json.loads(content[0])
                    self.assertEqual(mni_d, {"ms_id": ms_id, "network_interface_id": ni_id})
                with zf.open("zentral_macos_app_instance_0001.jsonl") as jl:
                    content = jl.read().decode("utf-8").splitlines()
                    self.assertEqual(len(content), 1)
                    oai_d = json.loads(content[0])
                    self.assertEqual(oai_d["team_id"], "ABCDE12345")
                    self.assertEqual(oai_d["executable_path"], "/Applications/Baller_path")
                    self.assertEqual(oai_d["cd_hash"], "0123456789abcdef0123456789abcdef01234567")
                    self.assertEqual(oai_d["signing_time"], "2024-01-02T03:04:05")
                    self.assertEqual(oai_d["secure_signing_time"], "2024-01-02T03:04:06")
                    # entitlements is jsonb, dumped as text by the full export (like extra_facts)
                    entitlements = oai_d["entitlements"]
                    if isinstance(entitlements, str):
                        entitlements = json.loads(entitlements)
                    self.assertEqual(entitlements, {"com.apple.security.app-sandbox": True,
                                                    "com.apple.security.network.client": True})
        default_storage.delete(result["filepath"])

    def commit_full_tree(self, serial_number, index, source_name="Zentral Tests"):
        marker = f"V{index}"
        source = {"module": "tests.zentral.io", "name": source_name}
        tree = {
            "source": source,
            "serial_number": serial_number,
            "business_unit": {"name": f"BU {marker}", "reference": f"bu-{marker}", "source": source},
            "os_version": {"name": "macOS", "major": 26, "minor": 0, "patch": 0, "build": f"26A{index}"},
            "system_info": {"computer_name": f"computer {marker}", "hardware_model": "Mac16,10"},
            "principal_user": {"source": {"type": "LOGGED_IN_USER", "properties": {"marker": marker}},
                               "unique_id": f"uid-{marker}",
                               "principal_name": f"user-{marker}",
                               "display_name": f"User {marker}"},
            "ec2_instance_metadata": {"instance_id": f"i-{marker}",
                                      "instance_type": "t4g.small",
                                      "architecture": "arm64",
                                      "region": "eu-central-1",
                                      "availability_zone": "eu-central-1a",
                                      "local_hostname": f"ip-{marker}",
                                      "mac": "0a:0b:0c:0d:0e:0f",
                                      "ami_id": f"ami-{marker}",
                                      "reservation_id": f"r-{marker}",
                                      "account_id": "123456789012"},
            "ec2_instance_tags": [{"key": "Name", "value": f"tag {marker}"}],
            "disks": [{"name": f"/dev/disk-{marker}", "size": 62826479616}],
            "network_interfaces": [{"interface": "en0",
                                    "mac": "b0:be:00:00:00:00",
                                    "address": f"10.0.0.{index}",
                                    "mask": "255.255.255.0"}],
            "certificates": [{"common_name": f"Zentral CA {marker}", "sha_256": sha_256(marker, "ca")}],
            "profiles": [{"uuid": f"e6dd0e0b-0f92-4a58-9d41-3a4c04a1b7d{index}",
                          "display_name": f"Profile {marker}",
                          "signed_by": {"common_name": f"Profile signer {marker}",
                                        "sha_256": sha_256(marker, "profile")}}],
            "osx_app_instances": [
                {"app": {"bundle_id": f"io.zentral.app{index}",
                         "bundle_name": f"App {marker}.app",
                         "bundle_version": str(index),
                         "bundle_version_str": f"{index}.0"},
                 "bundle_path": f"/Applications/App {marker}.app",
                 "team_id": "ABCDE12345",
                 "signed_by": {"common_name": f"Developer ID Application: {marker}",
                               "sha_256": sha_256(marker, "leaf"),
                               "signed_by": {"common_name": f"Developer ID CA {marker}",
                                             "sha_256": sha_256(marker, "intermediate"),
                                             "signed_by": root_certificate()}}},
            ],
            "android_apps": [{"display_name": f"Android {marker}", "version_name": f"{index}.0"}],
            "deb_packages": [{"name": f"deb-{marker}", "version": f"{index}.0"}],
            "ios_apps": [{"name": f"iOS {marker}", "version": f"{index}.0"}],
            "program_instances": [{"program": {"name": f"Program {marker}", "version": f"{index}.0"},
                                   "install_location": f"C:\\Program Files\\{marker}"}],
            "extra_facts": {"marker": marker},
        }
        _, ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        return ms

    def read_export(self, result):
        tables = {}
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                for name in zf.namelist():
                    # zentral_<table>_<index>.jsonl
                    table = name[len("zentral_"):].rsplit("_", 1)[0]
                    with zf.open(name) as jl:
                        tables.setdefault(table, []).extend(
                            json.loads(line) for line in jl.read().decode("utf-8").splitlines()
                        )
        default_storage.delete(result["filepath"])
        return tables

    def test_full_export_current_snapshots_only(self):
        serial_number = get_random_string(12)
        ms1 = self.commit_full_tree(serial_number, 1)
        ms2 = self.commit_full_tree(serial_number, 2)
        self.assertNotEqual(ms1.pk, ms2.pk)
        # the replaced snapshot is kept in the inventory
        self.assertTrue(MachineSnapshot.objects.filter(pk=ms1.pk).exists())
        # objects without a current snapshot
        MetaBusinessUnit.objects.create(name="Orphan MBU")
        Source.objects.commit({"module": "tests.zentral.io", "name": "Orphan Source"})

        tables = self.read_export(do_full_export())

        def values(table, column):
            return {row[column] for row in tables[table]}

        self.assertEqual(values("machine", "ms_id"), {ms2.pk})
        for table in ("machine_disks", "machine_network_interface", "machine_certificate", "machine_profile",
                      "machine_macos_app_instance", "machine_android_app", "machine_deb_package",
                      "machine_ec2_instance_tag", "machine_ios_app", "machine_program_instance"):
            self.assertEqual(values(table, "ms_id"), {ms2.pk}, table)
        self.assertEqual(values("business_unit", "name"), {"BU V2"})
        self.assertEqual(values("meta_business_unit", "name"), {"BU V2"})
        self.assertEqual(values("os_version", "build"), {"26A2"})
        self.assertEqual(values("principal_user", "unique_id"), {"uid-V2"})
        self.assertEqual(values("source", "name"), {"Zentral Tests"})
        self.assertEqual(values("system_info", "computer_name"), {"computer V2"})
        self.assertEqual(values("disk", "name"), {"/dev/disk-V2"})
        self.assertEqual(values("network_interface", "address"), {"10.0.0.2"})
        # the certificates of the snapshot, the signers of the app instances and of the profiles, and their chains
        self.assertEqual(values("certificate", "common_name"),
                         {"Zentral CA V2", "Profile signer V2",
                          "Developer ID Application: V2", "Developer ID CA V2", "Apple Root CA"})
        self.assertEqual(values("profile", "display_name"), {"Profile V2"})
        self.assertEqual(values("macos_app", "bundle_name"), {"App V2.app"})
        self.assertEqual(values("macos_app_instance", "bundle_path"), {"/Applications/App V2.app"})
        self.assertEqual(values("android_app", "display_name"), {"Android V2"})
        self.assertEqual(values("deb_package", "name"), {"deb-V2"})
        self.assertEqual(values("ec2_instance_metadata", "instance_id"), {"i-V2"})
        self.assertEqual(values("ec2_instance_tag", "value"), {"tag V2"})
        self.assertEqual(values("ios_app", "name"), {"iOS V2"})
        self.assertEqual(values("program", "name"), {"Program V2"})
        self.assertEqual(values("program_instance", "install_location"), {"C:\\Program Files\\V2"})

    def test_full_export_rolls_the_parts(self):
        self.commit_full_tree(get_random_string(12), 1)
        self.commit_full_tree(get_random_string(12), 2)
        result = do_full_export(max_temp_file_size=1)
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                machine_parts = sorted(n for n in zf.namelist() if n.startswith("zentral_machine_0"))
                self.assertEqual(machine_parts, ["zentral_machine_0001.jsonl", "zentral_machine_0002.jsonl"])
                for name in machine_parts:
                    with zf.open(name) as jl:
                        self.assertEqual(len(jl.read().decode("utf-8").splitlines()), 1)
        tables = self.read_export(result)
        self.assertEqual(len(tables["machine"]), 2)

    def test_full_export_referential_closure(self):
        serial_number = get_random_string(12)
        self.commit_full_tree(serial_number, 1)
        self.commit_full_tree(serial_number, 2)
        self.commit_full_tree(get_random_string(12), 3, source_name="Zentral Tests Bis")

        tables = self.read_export(do_full_export())
        self.assertEqual(set(tables), {name for name, _ in FULL_EXPORT_QUERIES})

        checked = set()
        for table, table_rows in tables.items():
            columns = set().union(*(row.keys() for row in table_rows))
            for column in sorted(columns):
                if column == "id" or not column.endswith("_id") or (table, column) == ("machine", "ms_id"):
                    continue
                if (table, column) in NOT_FOREIGN_KEYS or (table, column) in NOT_EXPORTED_TARGETS:
                    continue
                target = RENAMED_FOREIGN_KEYS.get((table, column), "machine" if column == "ms_id" else column[:-3])
                self.assertIn(target, tables,
                              f"{table}.{column} is not a known foreign key of the export: "
                              "add it to RENAMED_FOREIGN_KEYS, NOT_FOREIGN_KEYS or NOT_EXPORTED_TARGETS")
                target_ids = {row["ms_id" if target == "machine" else "id"] for row in tables[target]}
                values = {row[column] for row in table_rows if row[column] is not None}
                self.assertTrue(values, f"{table}.{column} has no value in the fixture")
                self.assertTrue(values <= target_ids, f"{table}.{column} has dangling references")
                checked.add((table, column))
        self.assertIn(("certificate", "signed_by_id"), checked)
        self.assertIn(("machine_macos_app_instance", "macos_app_instance_id"), checked)

    def test_export_transaction_inside_an_outer_transaction(self):
        # the test runs in a transaction: the export must not change its isolation level
        with export_transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute("show transaction_isolation")
                self.assertEqual(cursor.fetchone()[0], "read committed")

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
                 'executable_path': '/Applications/Baller_path',
                 'bundle_version': '123',
                 'bundle_version_str': '1.2.3',
                 'path': '',
                 'team_id': 'ABCDE12345',
                 'cd_hash': '0123456789abcdef0123456789abcdef01234567',
                 'signing_time': '2024-01-02 03:04:05',
                 'secure_signing_time': '2024-01-02 03:04:06',
                 'serial_number': serial_number,
                 'source_module': 'tests.zentral.io',
                 'source_name': 'Zentral Tests'}
            )
        default_storage.delete(result["filepath"])


class InventoryExportTransactionTests(TransactionTestCase):
    def test_export_transaction_repeatable_read(self):
        with export_transaction() as connection:
            with connection.cursor() as cursor:
                cursor.execute("show transaction_isolation")
                self.assertEqual(cursor.fetchone()[0], "repeatable read")
