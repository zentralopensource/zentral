from django.urls import reverse
from django.test import TestCase
from prometheus_client.parser import text_string_to_metric_families
from zentral.contrib.inventory.models import MachineSnapshotCommit


class PrometheusViewsTestCase(TestCase):
    def test_prometheus_metrics_403(self):
        response = self.client.get(reverse("inventory:prometheus_metrics"))
        self.assertEqual(response.status_code, 403)

    def test_prometheus_metrics_200(self):
        response = self.client.get(reverse("inventory:prometheus_metrics"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        self.assertContains(response, "zentral_inventory_os_versions", status_code=200)
        self.assertContains(response, "zentral_inventory_osx_apps", status_code=200)

    def test_prometheus_metrics_with_machine_snapshot(self):
        tree = {
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": "0123456789",
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ]
        }
        _, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        source_id = ms.source.pk
        response = self.client.get(reverse("inventory:prometheus_metrics"),
                                   HTTP_AUTHORIZATION="Bearer CHANGE ME!!!")
        labels_dict = {}
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            sample = family.samples[0]
            self.assertEqual(sample.value, 1)  # only one machine in inventory
            labels_dict[sample.name] = sample.labels
        self.assertEqual(labels_dict['zentral_inventory_osx_apps'],
                         {'name': 'Baller.app',
                          'source': 'tests.zentral.io#{}'.format(source_id),
                          'version_str': '1.2.3'})
        self.assertEqual(labels_dict['zentral_inventory_os_versions'],
                         {'build': '_',
                          'major': '10',
                          'minor': '11',
                          'name': 'OS X',
                          'patch': '1',
                          'source': 'tests.zentral.io#{}'.format(source_id)})
