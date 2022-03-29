from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.probes.conf import all_probes, all_probes_dict
from zentral.core.probes.models import ProbeSource


class ProbesConfTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.inactive_probe_source = ProbeSource.objects.create(model="BaseProbe",
                                                               name=get_random_string(12),
                                                               status=ProbeSource.INACTIVE,
                                                               body={})
        cls.inactive_probe = cls.inactive_probe_source.load()
        cls.probe_source = ProbeSource.objects.create(model="BaseProbe",
                                                      name=get_random_string(12),
                                                      status=ProbeSource.ACTIVE,
                                                      body={})
        cls.probe = cls.probe_source.load()

    def test_all_probes(self):
        all_probes.clear()
        self.assertEqual(list(all_probes), [self.probe])

    def test_all_probes_dict(self):
        all_probes_dict.clear()
        self.assertEqual(all_probes_dict[self.probe.pk], self.probe)
        with self.assertRaises(KeyError):
            all_probes_dict[self.inactive_probe.pk]
