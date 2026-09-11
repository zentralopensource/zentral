import csv
from datetime import datetime, timedelta
from unittest.mock import patch
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile
import pyarrow.parquet as pq
from django.core.files.storage import default_storage
from django.test import TestCase, TransactionTestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshot, MachineSnapshotCommit, MetaBusinessUnit, Source
from zentral.contrib.inventory.utils import (do_full_export,
                                             export_machine_macos_app_instances,
                                             export_machine_snapshots)
from zentral.contrib.inventory.utils.full_export import (FULL_EXPORT_QUERIES, FULL_EXPORT_TABLE_NAMES, TempFile,
                                                         export_transaction, iter_tables, save_export_object)
from zentral.utils.parquet import arrow_schema


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
                    ['manifest.json',
                     'zentral_business_unit_0001.jsonl',
                     'zentral_disk_0001.jsonl',
                     'zentral_machine_0001.jsonl',
                     'zentral_machine_disk_0001.jsonl',
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
                with zf.open("zentral_machine_disk_0001.jsonl") as jl:
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
            "public_ip_address": f"203.0.113.{index}",
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
                    if not name.startswith("zentral_"):
                        continue
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
        for table in ("machine_disk", "machine_network_interface", "machine_certificate", "machine_profile",
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

    def test_iter_tables_window_size(self):
        self.commit_machine_snapshot()
        self.commit_machine_snapshot()
        for table, description, batches in iter_tables(["machine"], window_size=1):
            self.assertEqual(table, "machine")
            self.assertIn("serial_number", [c.name for c in description])
            # one fetch per row
            self.assertEqual([len(batch) for batch in batches], [1, 1])

    def test_full_export_manifest(self):
        self.commit_full_tree(get_random_string(12), 1)
        self.commit_full_tree(get_random_string(12), 2)
        result = do_full_export(max_temp_file_size=1)
        manifest = result["manifest"]
        self.assertEqual(manifest["version"], 1)
        self.assertRegex(manifest["export_id"], r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
        self.assertRegex(manifest["exported_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(manifest["format"], "JSONL")
        self.assertEqual(list(manifest["tables"]), FULL_EXPORT_TABLE_NAMES)
        self.assertEqual(result["filepath"], f"exports/full_inventory_export-{manifest['export_id']}.zip")
        self.assertEqual(result["headers"]["Content-Disposition"],
                         f'attachment; filename="full_inventory_export-{manifest["export_id"]}.zip"')
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                self.assertEqual(json.loads(zf.read("manifest.json")), manifest)
                self.assertNotIn("manifest.json", manifest["files"])
                self.assertEqual(set(manifest["files"]), set(zf.namelist()) - {"manifest.json"})
                for name, file_manifest in manifest["files"].items():
                    content = zf.read(name)
                    self.assertEqual(file_manifest["size"], len(content))
                    self.assertEqual(file_manifest["sha256"], hashlib.sha256(content).hexdigest())
                    lines = content.decode("utf-8").splitlines()
                    # max_temp_file_size=1: one row per file
                    self.assertEqual(len(lines), 1)
                    self.assertEqual(file_manifest["rows"], 1)
                    table_manifest = manifest["tables"][file_manifest["table"]]
                    self.assertIn(name, table_manifest["files"])
                    self.assertEqual([c["name"] for c in table_manifest["columns"]], list(json.loads(lines[0])))
        for table, table_manifest in manifest["tables"].items():
            self.assertTrue(table_manifest["rows"] > 0, table)
            self.assertEqual(table_manifest["rows"], len(table_manifest["files"]))
        default_storage.delete(result["filepath"])

    def test_full_export_tables(self):
        self.commit_machine_snapshot()
        result = do_full_export(tables=["machine_disk", "machine", "machine"])
        # canonical order, no duplicates
        self.assertEqual(list(result["manifest"]["tables"]), ["machine", "machine_disk"])
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                self.assertEqual(sorted(zf.namelist()),
                                 ["manifest.json", "zentral_machine_0001.jsonl", "zentral_machine_disk_0001.jsonl"])
        default_storage.delete(result["filepath"])

    def test_full_export_unknown_tables(self):
        with self.assertRaises(ValueError) as cm:
            do_full_export(tables=["machine", "yolo", "fomo"])
        self.assertEqual(cm.exception.args[0], "Unknown tables: fomo, yolo")

    def test_full_export_no_tables(self):
        with self.assertRaises(ValueError) as cm:
            do_full_export(tables=[])
        self.assertEqual(cm.exception.args[0], "At least one table is required")

    def test_full_export_empty_table(self):
        # no Debian packages in this tree
        self.commit_machine_snapshot()
        result = do_full_export(tables=["deb_package", "machine_deb_package"])
        manifest = result["manifest"]
        self.assertEqual(manifest["files"], {})
        self.assertEqual(manifest["tables"]["deb_package"]["rows"], 0)
        self.assertEqual(manifest["tables"]["deb_package"]["files"], [])
        # the columns are known without a row
        self.assertIn({"name": "name"}, manifest["tables"]["deb_package"]["columns"])
        self.assertEqual(manifest["tables"]["machine_deb_package"]["columns"],
                         [{"name": "ms_id"}, {"name": "deb_package_id"}])
        with default_storage.open(result["filepath"]) as f:
            with zipfile.ZipFile(f) as zf:
                self.assertEqual(zf.namelist(), ["manifest.json"])
        default_storage.delete(result["filepath"])

    def test_temp_file(self):
        f = TempFile()
        f.write(b"yo")
        f.flush()
        f.write(b"lo")
        self.assertEqual(f.tell(), 4)
        self.assertFalse(f.closed)
        f.close()
        self.assertTrue(f.closed)
        self.assertEqual(f.size, 4)
        self.assertEqual(f.hexdigest(), hashlib.sha256(b"yolo").hexdigest())
        with open(f.path, "rb") as rf:
            self.assertEqual(rf.read(), b"yolo")
        os.unlink(f.path)

    def test_save_export_object_renamed(self):
        with patch("zentral.contrib.inventory.utils.full_export.default_storage.save",
                   return_value="exports/other") as save:
            with self.assertRaises(RuntimeError) as cm:
                save_export_object("exports/yolo", io.BytesIO(b"yolo"))
        save.assert_called_once()
        self.assertEqual(cm.exception.args[0], "Export object exports/yolo saved as exports/other")

    def test_full_export_unknown_format(self):
        with self.assertRaises(ValueError) as cm:
            do_full_export(export_format="YOLO")
        self.assertEqual(cm.exception.args[0], "Unknown export format: YOLO")

    # PARQUET

    def read_parquet_export(self, result):
        manifest = result["manifest"]
        location = manifest["location"]
        tables = {}
        for key, file_manifest in manifest["files"].items():
            with default_storage.open(location + key) as f:
                content = f.read()
            default_storage.delete(location + key)
            self.assertEqual(file_manifest["size"], len(content))
            self.assertEqual(file_manifest["sha256"], hashlib.sha256(content).hexdigest())
            pa_table = pq.read_table(io.BytesIO(content))
            self.assertEqual(pa_table.num_rows, file_manifest["rows"])
            table_manifest = manifest["tables"][file_manifest["table"]]
            self.assertIn(key, table_manifest["files"])
            self.assertEqual([(field.name, str(field.type)) for field in pa_table.schema],
                             [(c["name"], c["type"]) for c in table_manifest["columns"]])
            tables.setdefault(file_manifest["table"], []).extend(pa_table.to_pylist())
        with default_storage.open(location + "manifest.json") as f:
            self.assertEqual(json.load(f), manifest)
        default_storage.delete(location + "manifest.json")
        return tables

    def test_full_export_parquet(self):
        serial_number = get_random_string(12)
        self.commit_full_tree(serial_number, 1)
        ms2 = self.commit_full_tree(serial_number, 2)
        ms3 = self.commit_full_tree(get_random_string(12), 3, source_name="Zentral Tests Bis")
        result = do_full_export(export_format="PARQUET")
        self.assertEqual(set(result), {"manifest"})
        manifest = result["manifest"]
        self.assertEqual(manifest["format"], "PARQUET")
        self.assertEqual(manifest["location"], f"exports/inventory/{manifest['export_id']}/")
        self.assertEqual(set(manifest["tables"]), set(FULL_EXPORT_TABLE_NAMES))
        self.assertNotIn("manifest.json", manifest["files"])
        for key, file_manifest in manifest["files"].items():
            self.assertEqual(key, f"{file_manifest['table']}/{file_manifest['table']}-00001.parquet")
        tables = self.read_parquet_export(result)
        for table, table_manifest in manifest["tables"].items():
            self.assertEqual(len(tables[table]), table_manifest["rows"], table)
            self.assertTrue(table_manifest["rows"] > 0, table)
            self.assertTrue(all(c["nullable"] for c in table_manifest["columns"]), table)
        # the current snapshots only
        self.assertEqual({row["ms_id"] for row in tables["machine"]}, {ms2.pk, ms3.pk})
        row = next(row for row in tables["machine"] if row["ms_id"] == ms2.pk)
        # typed columns: timestamps are UTC, JSON is text
        self.assertEqual(row["mt_created_at"].utcoffset(), timedelta(0))
        self.assertEqual(json.loads(row["extra_facts"]), {"marker": "V2"})
        # inet values are text
        self.assertEqual(row["public_ip_address"], "203.0.113.2")
        self.assertEqual(next(row for row in tables["disk"] if row["name"] == "/dev/disk-V2")["size"], 62826479616)
        self.assertEqual(next(row for row in tables["network_interface"] if row["address"] == "10.0.0.2")["mask"],
                         "255.255.255.0")

    def test_full_export_parquet_empty_table(self):
        # no Debian packages in this tree
        self.commit_machine_snapshot()
        result = do_full_export(tables=["deb_package"], export_format="PARQUET")
        manifest = result["manifest"]
        key = "deb_package/deb_package-00001.parquet"
        # a table without a row keeps its schema in one file
        self.assertEqual(manifest["tables"]["deb_package"]["rows"], 0)
        self.assertEqual(manifest["tables"]["deb_package"]["files"], [key])
        self.assertEqual(manifest["files"][key]["rows"], 0)
        self.assertIn({"name": "name", "type": "string", "nullable": True},
                      manifest["tables"]["deb_package"]["columns"])
        tables = self.read_parquet_export(result)
        self.assertEqual(tables, {"deb_package": []})

    def test_full_export_parquet_rolls_the_parts(self):
        self.commit_full_tree(get_random_string(12), 1)
        self.commit_full_tree(get_random_string(12), 2)
        result = do_full_export(tables=["machine"], export_format="PARQUET", max_part_size=1, window_size=1)
        manifest = result["manifest"]
        self.assertEqual(manifest["tables"]["machine"]["files"],
                         ["machine/machine-00001.parquet", "machine/machine-00002.parquet"])
        self.assertEqual([f["rows"] for f in manifest["files"].values()], [1, 1])
        tables = self.read_parquet_export(result)
        self.assertEqual(len(tables["machine"]), 2)

    def test_full_export_parquet_schemas(self):
        # The Parquet schema of the export is a contract. A model change that reaches the export must update
        # tests/inventory/full_export_parquet_schemas.json: run the test with ZENTRAL_UPDATE_PARQUET_SCHEMAS=1.
        schemas = {}
        for table, description, _ in iter_tables(FULL_EXPORT_TABLE_NAMES, window_size=1):
            schemas[table] = [[column.name, str(field.type)]
                              for column, field in zip(description, arrow_schema(description))]
        schemas_path = Path(__file__).parent / "full_export_parquet_schemas.json"
        if os.environ.get("ZENTRAL_UPDATE_PARQUET_SCHEMAS"):
            schemas_path.write_text(json.dumps(schemas, indent=2) + "\n")
        with schemas_path.open() as f:
            self.assertEqual(schemas, json.load(f))

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
