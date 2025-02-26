from datetime import datetime, timedelta
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import ConfigDict, settings
from zentral.contrib.inventory.models import (
    MachineSnapshotCommit,
    MachineTag,
    Tag,
    Taxonomy,
)


class PrometheusViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        tree = {
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": "0123456789",
            "system_info": {"hardware_model": "MacBookPro14,2"},
            "os_version": {"name": "OS X", "major": 10, "minor": 11, "patch": 1},
            "android_apps": [
                {"display_name": "AndroidApp1", "version_name": "1.1"},
                {"display_name": "AndroidApp2", "version_name": "1.2"},
            ],
            "ios_apps": [
                {"name": "2Password", "version": "1.1"},
                {"name": "3Password", "version": "1.2"},
            ],
            "osx_app_instances": [
                {
                    "app": {
                        "bundle_id": "io.zentral.baller",
                        "bundle_name": "Baller",
                        "bundle_version": "123",
                        "bundle_version_str": "1.2.3",
                    },
                    "bundle_path": "/Applications/Baller.app",
                },
                {
                    "app": {
                        "bundle_id": "io.zentral.no",
                        "bundle_name": "No",
                        "bundle_version": "123",
                        "bundle_version_str": "1.2.3",
                    },
                    "bundle_path": "/Applications/No.app",
                },
                {
                    "app": {
                        "bundle_id": "io.zentral.no",
                        "bundle_name": "Oui",
                        "bundle_version": "689",
                        "bundle_version_str": "6.8.9",
                    },
                    "bundle_path": "/Applications/No.app",
                },
            ],
            "deb_packages": [
                {"name": "deb_package_1", "version": "1.1"},
                {"name": "deb_package_2", "version": "1.2"},
            ],
            "program_instances": [
                {
                    "program": {"name": "program_1", "version": "1.1"},
                    "install_source": "tests",
                },
                {
                    "program": {"name": "program_2", "version": "1.2"},
                    "install_source": "tests",
                },
            ],
            "last_seen": datetime.utcnow() - timedelta(days=2),
        }
        _, cls.ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.source_id = cls.ms.source.pk
        tree = {
            "source": {"module": "tests2.zentral.io", "name": "Zentral Tests2"},
            "serial_number": "0123456789",
            "system_info": {"hardware_model": "MacBookPro14,2"},
            "os_version": {
                "name": "OS X",
                "major": 12,
                "minor": 2,
                "patch": 0,
                "version": "(a)",
            },
            "android_apps": [
                {"display_name": "AndroidApp1", "version_name": "2.1"},
                {"display_name": "AndroidApp2", "version_name": "2.2"},
            ],
            "ios_apps": [
                {"name": "2Password", "version": "2.1"},
                {"name": "3Password", "version": "2.2"},
            ],
            "osx_app_instances": [
                {
                    "app": {
                        "bundle_id": "io.zentral.baller",
                        "bundle_name": "Baller",
                        "bundle_version": "123",
                        "bundle_version_str": "2.3.4",
                    },
                    "bundle_path": "/Applications/Baller.app",
                },
                {
                    "app": {
                        "bundle_id": "io.zentral.no",
                        "bundle_name": "No",
                        "bundle_version": "123",
                        "bundle_version_str": "2.3.4",
                    },
                    "bundle_path": "/Applications/No.app",
                },
                {
                    "app": {
                        "bundle_id": "io.zentral.no",
                        "bundle_name": "Oui",
                        "bundle_version": "678",
                        "bundle_version_str": "6.8.9",
                    },
                    "bundle_path": "/Applications/No.app",
                },
            ],
            "deb_packages": [
                {"name": "deb_package_1", "version": "2.1"},
                {"name": "deb_package_2", "version": "2.2"},
            ],
            "program_instances": [
                {
                    "program": {"name": "program_1", "version": "2.1"},
                    "install_source": "tests",
                },
                {
                    "program": {"name": "program_2", "version": "2.2"},
                    "install_source": "tests",
                },
            ],
            "last_seen": datetime.utcnow() - timedelta(days=13),
        }
        _, cls.ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        cls.source_id2 = cls.ms2.source.pk

        # tags
        cls.tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(tag=cls.tag, serial_number=get_random_string(12))
        cls.taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        cls.taxonomy_tag = Tag.objects.create(
            name=get_random_string(12), taxonomy=cls.taxonomy
        )
        for i in range(2):
            MachineTag.objects.create(
                tag=cls.taxonomy_tag, serial_number=get_random_string(12)
            )

    # utils

    def _assertSamples(self, families, samples, only_family=None):
        d = {}
        for family in families:
            if only_family and only_family != family.name:
                continue
            sample_dict = d.setdefault(family.name, {})
            for sample in family.samples:
                serialized_sample_items = []
                for label in sorted(sample.labels.keys()):
                    serialized_sample_items.append(label)
                    serialized_sample_items.append(sample.labels[label])
                sample_dict[tuple(serialized_sample_items)] = sample.value
        self.assertEqual(d, samples)

    # tests

    def test_prometheus_metrics_403(self):
        response = self.client.get(reverse("inventory_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_prometheus_metrics_osx_apps_bundle_ids(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "osx_apps": {
                        "sources": ["zentral tests"],
                        "bundle_ids": ["io.zentral.baller"],
                    },
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_osx_apps_bucket': {
                    ('le', '1', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 0.0,
                    ('le', '7', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '14', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '30', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '45', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '90', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '+Inf', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                },
            },
            only_family="zentral_inventory_osx_apps_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_osx_apps_bundle_names(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "osx_apps": {
                        "sources": ["zentral tests"],
                        "bundle_names": ["Baller"],
                    },
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_osx_apps_bucket': {
                    ('le', '1', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 0.0,
                    ('le', '7', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '14', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '30', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '45', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '90', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '+Inf', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                },
            },
            only_family="zentral_inventory_osx_apps_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_osx_apps_all(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "osx_apps": {
                        "sources": ["zentral tests"],
                        "bundle_ids": ["io.zentral.baller"],
                        "bundle_names": ["Oui"],
                    },
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_osx_apps_bucket': {
                    ('le', '1', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 0.0,
                    ('le', '7', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '14', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '30', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '45', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '90', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '+Inf', 'name', 'Baller', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2.3'): 1.0,
                    ('le', '1', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 0.0,
                    ('le', '7', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                    ('le', '14', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                    ('le', '30', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                    ('le', '45', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                    ('le', '90', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                    ('le', '+Inf', 'name', 'Oui', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '6.8.9'): 1.0,
                },
            },
            only_family="zentral_inventory_osx_apps_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_android_apps(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "android_apps": {
                        "sources": ["zentral tests2"],
                        "names": ["AndroidApp1"],
                    },
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_android_apps_bucket': {
                    ('le', '1', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 0.0,
                    ('le', '7', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 0.0,
                    ('le', '14', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 1.0,
                    ('le', '30', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 1.0,
                    ('le', '45', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 1.0,
                    ('le', '90', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 1.0,
                    ('le', '+Inf', 'name', 'AndroidApp1', 'source_id', str(self.source_id2),
                     'source_name', 'Zentral Tests2', 'version', '2.1'): 1.0,
                },
            },
            only_family="zentral_inventory_android_apps_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_ios_apps(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "ios_apps": {"sources": ["zentral tests"], "names": ["3Password"]},
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_ios_apps_bucket': {
                    ('le', '1', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 0.0,
                    ('le', '7', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                    ('le', '14', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                    ('le', '30', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                    ('le', '45', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                    ('le', '90', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                    ('le', '+Inf', 'name', '3Password', 'source_id', str(self.source_id),
                     'source_name', 'Zentral Tests', 'version', '1.2'): 1.0,
                },
            },
            only_family="zentral_inventory_ios_apps_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_deb_packages(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "deb_packages": {
                        "sources": ["zentral tests2"],
                        "names": ["deb_package_2"],
                    },
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_active_machines_bucket': {
                    ('le', '1', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 0.0,
                    ('le', '7', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 0.0,
                    ('le', '14', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '30', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '45', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '90', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '+Inf', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                },
            },
            only_family="zentral_inventory_active_machines_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_programs(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict(
                {
                    "programs": {"sources": ["zentral tests"], "names": ["program_1"]},
                }
            )
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_active_machines_bucket': {
                    ('le', '1', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 0.0,
                    ('le', '7', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                    ('le', '14', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                    ('le', '30', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                    ('le', '45', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                    ('le', '90', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                    ('le', '+Inf', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id), 'source_name', 'Zentral Tests'): 1.0,
                },
            },
            only_family="zentral_inventory_active_machines_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_os_versions(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict({"os_versions": {"sources": ["zentral tests2"]}})
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_os_versions_bucket': {
                    ('build', '', 'le', '1', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 0.0,
                    ('build', '', 'le', '7', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 0.0,
                    ('build', '', 'le', '14', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 1.0,
                    ('build', '', 'le', '30', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 1.0,
                    ('build', '', 'le', '45', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 1.0,
                    ('build', '', 'le', '90', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 1.0,
                    ('build', '', 'le', '+Inf', 'major', '12',
                     'minor', '2', 'name', 'OS X', 'patch', '0',
                     'platform', 'MACOS', 'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2',
                     'version', '(a)'): 1.0,
                },
            },
            only_family="zentral_inventory_os_versions_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_active_machines(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop(
            "metrics_options", None
        )
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = (
            ConfigDict({"os_versions": {"sources": ["zentral tests2"]}})
        )
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_active_machines_bucket': {
                    ('le', '1', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 0.0,
                    ('le', '7', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 0.0,
                    ('le', '14', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '30', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '45', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '90', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                    ('le', '+Inf', 'machine_type', 'LAPTOP', 'platform', 'MACOS',
                     'source_id', str(self.source_id2), 'source_name', 'Zentral Tests2'): 1.0,
                },
            },
            only_family="zentral_inventory_active_machines_bucket",
        )
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"][
                "metrics_options"
            ] = old_config

    def test_prometheus_metrics_machine_tags(self):
        response = self.client.get(
            reverse("inventory_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_inventory_machine_tags': {
                    ('tag', self.taxonomy_tag.name, 'taxonomy', self.taxonomy.name): 2.0,
                    ('tag', self.tag.name, 'taxonomy', '_'): 1.0,
                },
            },
            only_family="zentral_inventory_machine_tags",
        )
