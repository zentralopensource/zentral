from django.urls import reverse
from django.test import TestCase
from prometheus_client.parser import text_string_to_metric_families
from zentral.contrib.inventory.models import MachineSnapshot


class InventoryViewsTestCase(TestCase):
    def test_prometheus_metrics(self):
        response = self.client.get(reverse("inventory:prometheus_metrics"))
        self.assertContains(response, "zentral_inventory_os_versions", status_code=200)
        self.assertContains(response, "zentral_inventory_osx_apps", status_code=200)

    def test_prometheus_metrics_with_machine_snapshot(self):
        tree = {
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "machine": {"serial_number": "0123456789"},
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ]
        }
        MachineSnapshot.objects.commit(tree)
        response = self.client.get(reverse("inventory:prometheus_metrics"))
        labels_dict = {}
        for family in text_string_to_metric_families(response.content.decode('utf-8')):
            self.assertEqual(len(family.samples), 1)
            name, labels, value = family.samples[0]
            self.assertEqual(value, 1)  # only one machine in inventory
            labels_dict[name] = labels
        self.assertEqual(labels_dict['zentral_inventory_osx_apps'],
                         {'name': 'Baller.app',
                          'source': 'tests.zentral.io#1',
                          'version_str': '1.2.3'})
        self.assertEqual(labels_dict['zentral_inventory_os_versions'],
                         {'build': '_',
                          'major': '10',
                          'minor': '11',
                          'name': 'OS X',
                          'patch': '1',
                          'source': 'tests.zentral.io#1'})
