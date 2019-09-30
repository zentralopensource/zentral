from datetime import datetime
import os
from django.test import SimpleTestCase
from zentral.contrib.munki.utils import iter_certificates, is_ca, prepare_ms_tree_certificates


class TestMunkiTreeCertificates(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        tlsdir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "../../conf/start/docker/tls/")
        cls.cert = open(os.path.join(tlsdir, "zentral.crt")).read()
        cls.ca_cert = open(os.path.join(tlsdir, "zentral_ca.crt")).read()
        cls.certs = [cls.cert, cls.ca_cert]

    def test_is_ca(self):
        cert, ca_cert = list(iter_certificates(self.certs))
        self.assertEqual(is_ca(cert), False)
        self.assertEqual(is_ca(ca_cert), True)

    def test_ms_tree_certificates(self):
        ms_tree = {"pem_certificates": self.certs}
        prepare_ms_tree_certificates(ms_tree)
        self.assertEqual(
            ms_tree["certificates"],
            [{'common_name': 'zentral',
              'sha_1': 'f373928e75dfa460726c92c3263e664816b504d5',
              'signed_by': {'common_name': 'Zentral CA',
                            'organization': 'Zentral',
                            'organizational_unit': 'IT'},
              'valid_from': datetime(2019, 6, 27, 10, 56, 5),
              'valid_until': datetime(2029, 6, 24, 10, 56, 5)}]
        )
