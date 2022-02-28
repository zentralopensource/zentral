import datetime
import os
from django.test import SimpleTestCase
from zentral.utils.certificates import is_ca, iter_cert_trees, iter_certificates, parse_apple_dev_id


class CertificatesTestCate(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        tlsdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "../../conf/start/docker/tls/")
        cls.cert = open(os.path.join(tlsdir, "zentral.crt")).read()
        cls.ca_cert = open(os.path.join(tlsdir, "zentral_ca.crt")).read()
        cls.fullchain = cls.cert + cls.ca_cert

    def test_is_ca(self):
        cert, ca_cert = list(iter_certificates(self.fullchain))
        self.assertEqual(is_ca(cert), False)
        self.assertEqual(is_ca(ca_cert), True)

    def test_dev_id_match(self):
        self.assertEqual(
            parse_apple_dev_id("Developer ID Application: Mozilla Corporation (43AQ936H96)"),
            ('Mozilla Corporation', '43AQ936H96')
        )

    def test_dev_id_no_match(self):
        with self.assertRaises(ValueError) as cm:
            parse_apple_dev_id("le temps des cerises")
        self.assertEqual(cm.exception.args[0], "Not an Apple developer ID")

    def test_iter_cert_trees(self):
        self.assertEqual(
            list(iter_cert_trees(self.fullchain)),
            [{'common_name': 'zentral',
              'sha_1': 'f373928e75dfa460726c92c3263e664816b504d5',
              'signed_by': {'common_name': 'Zentral CA',
                            'organization': 'Zentral',
                            'organizational_unit': 'IT'},
              'valid_from': datetime.datetime(2019, 6, 27, 10, 56, 5),
              'valid_until': datetime.datetime(2029, 6, 24, 10, 56, 5)},
             {'common_name': 'Zentral CA',
              'organization': 'Zentral',
              'organizational_unit': 'IT',
              'sha_1': '9a2dc1b26c23776aa828aaaae6d5284981e81f8a',
              'signed_by': {'common_name': 'Zentral CA',
                            'organization': 'Zentral',
                            'organizational_unit': 'IT'},
              'valid_from': datetime.datetime(2017, 10, 16, 15, 14, 38),
              'valid_until': datetime.datetime(2027, 10, 14, 15, 14, 38)}]
        )
