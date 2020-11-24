from django.test import SimpleTestCase
from zentral.contrib.inventory.utils import clean_ip_address


class CleanIPAddressTestCase(SimpleTestCase):
    def test_ipv4(self):
        for value, result in ((None, None),
                              (123, None),
                              ("127.0.0.1 ", "127.0.0.1"),
                              (" 10.12.13.17 ", "10.12.13.17"),
                              ("127.0000.0.1", None)):
            self.assertEqual(clean_ip_address(value), result)

    def test_ipv6(self):
        for value, result in (("0:0:0:0:0:0:0:1", "::1"),
                              ("2001:db8::1", "2001:db8::1"),
                              ("::FFFF:129.144.52.38", "129.144.52.38"),
                              ):
            self.assertEqual(clean_ip_address(value), result)
