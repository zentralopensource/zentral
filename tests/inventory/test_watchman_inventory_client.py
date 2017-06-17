from django.test import SimpleTestCase
from zentral.contrib.inventory.clients.watchman import InventoryClient


class ProcessorRegexTestCase(SimpleTestCase):
    def test_with_core(self):
        processor = "Intel(R) Core(TM) i7-3720QM CPU @ 2.60GHz 2594 (1 processor)"
        d = InventoryClient._system_info_update_dict_from_processor(processor)
        self.assertDictEqual(d, {'cpu_brand': 'Intel(R) Core(TM) i7-3720QM CPU @ 2.60GHz 2594'})

    def test_without_core(self):
        processor = "Intel Core i5 2.7 GHz (4 core 1 processor)"
        d = InventoryClient._system_info_update_dict_from_processor(processor)
        self.assertDictEqual(d, {'cpu_brand': 'Intel Core i5 2.7 GHz', 'cpu_physical_cores': 4})

    def test_unknown(self):
        processor = "Godzilla yo    "
        d = InventoryClient._system_info_update_dict_from_processor(processor)
        self.assertDictEqual(d, {'cpu_brand': 'Godzilla yo'})
