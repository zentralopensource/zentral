from django.urls import reverse
from django.test import TestCase
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import ConfigDict, settings
from zentral.contrib.inventory.models import MachineSnapshotCommit


class PrometheusViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        tree = {
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"},
                {'app': {'bundle_id': 'io.zentral.no',
                         'bundle_name': 'No',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/No.app"}
            ],
            "deb_packages": [
                {"name": "deb_package_1", "version": "1.1"},
                {"name": "deb_package_2", "version": "1.2"},
            ],
            "program_instances": [
                {"program": {"name": "program_1", "version": "1.1"},
                 "install_source": "tests"},
                {"program": {"name": "program_2", "version": "1.2"},
                 "install_source": "tests"},
            ]
        }
        _, cls.ms, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        tree = {
            "source": {"module": "tests2.zentral.io", "name": "Zentral Tests2"},
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 12, 'minor': 2},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller',
                         'bundle_version': '123',
                         'bundle_version_str': '2.3.4'},
                 'bundle_path': "/Applications/Baller.app"},
                {'app': {'bundle_id': 'io.zentral.no',
                         'bundle_name': 'No',
                         'bundle_version': '123',
                         'bundle_version_str': '2.3.4'},
                 'bundle_path': "/Applications/No.app"}
            ],
            "deb_packages": [
                {"name": "deb_package_1", "version": "2.1"},
                {"name": "deb_package_2", "version": "2.2"},
            ],
            "program_instances": [
                {"program": {"name": "program_1", "version": "2.1"},
                 "install_source": "tests"},
                {"program": {"name": "program_2", "version": "2.2"},
                 "install_source": "tests"},
            ]
        }
        _, cls.ms2, _ = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)

    def test_prometheus_metrics_403(self):
        response = self.client.get(reverse("inventory_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_prometheus_metrics_osx_apps(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop("metrics_options", None)
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = ConfigDict({
            "osx_apps": {"sources": ["zentral tests"], "bundle_ids": ["io.zentral.baller"]},
        })
        response = self.client.get(reverse("inventory_metrics:all"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        self.assertEqual(response.status_code, 200)
        seen = False
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            sample = family.samples[0]
            self.assertEqual(sample.name, "zentral_inventory_osx_apps")
            self.assertEqual(sample.value, 1)  # only one machine in inventory
            self.assertEqual(sample.labels,
                             {'name': 'Baller',
                              'source_name': self.ms.source.name,
                              'source_id': str(self.ms.source.pk),
                              'version': '1.2.3'})
            self.assertFalse(seen)  # only osx apps
            seen = True
        self.assertTrue(seen)
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = old_config

    def test_prometheus_metrics_deb_packages(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop("metrics_options", None)
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = ConfigDict({
            "deb_packages": {"sources": ["zentral tests2"], "names": ["deb_package_2"]},
        })
        response = self.client.get(reverse("inventory_metrics:all"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        self.assertEqual(response.status_code, 200)
        seen = False
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            sample = family.samples[0]
            self.assertEqual(sample.name, "zentral_inventory_deb_packages")
            self.assertEqual(sample.value, 1)  # only one machine in inventory
            self.assertEqual(sample.labels,
                             {'name': 'deb_package_2',
                              'source_name': self.ms2.source.name,
                              'source_id': str(self.ms2.source.pk),
                              'version': '2.2'})
            self.assertFalse(seen)  # only deb packages
            seen = True
        self.assertTrue(seen)
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = old_config

    def test_prometheus_metrics_programs(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop("metrics_options", None)
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = ConfigDict({
            "programs": {"sources": ["zentral tests"], "names": ["program_1"]},
        })
        response = self.client.get(reverse("inventory_metrics:all"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        self.assertEqual(response.status_code, 200)
        seen = False
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            sample = family.samples[0]
            self.assertEqual(sample.name, "zentral_inventory_programs")
            self.assertEqual(sample.value, 1)  # only one machine in inventory
            self.assertEqual(sample.labels,
                             {'name': 'program_1',
                              'source_name': self.ms.source.name,
                              'source_id': str(self.ms.source.pk),
                              'version': '1.1'})
            self.assertFalse(seen)  # only programs
            seen = True
        self.assertTrue(seen)
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = old_config

    def test_prometheus_metrics_os_versions(self):
        old_config = settings._collection["apps"]["zentral.contrib.inventory"].pop("metrics_options", None)
        settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = ConfigDict({
            "os_versions": {"sources": ["zentral tests2"]}
        })
        response = self.client.get(reverse("inventory_metrics:all"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        self.assertEqual(response.status_code, 200)
        seen = False
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            sample = family.samples[0]
            self.assertEqual(sample.name, "zentral_inventory_os_versions")
            self.assertEqual(sample.value, 1)  # only one machine in inventory
            self.assertEqual(sample.labels,
                             {'build': '_',
                              'major': '12',
                              'minor': '2',
                              'name': 'OS X',
                              'patch': '_',
                              'source_name': self.ms2.source.name,
                              'source_id': str(self.ms2.source.pk)})
            self.assertFalse(seen)  # only os versions
            seen = True
        self.assertTrue(seen)
        if old_config:
            settings._collection["apps"]["zentral.contrib.inventory"]["metrics_options"] = old_config
