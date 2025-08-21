from unittest.mock import Mock, patch
from django.test import TestCase
from zentral.contrib.mdm.models import Platform
from zentral.contrib.mdm.cert_issuer_backends import (CertIssuerBackend,
                                                      get_cached_cert_issuer_backend, test_acme_payload)
from zentral.contrib.mdm.cert_issuer_backends.base import CertIssuer, CertIssuerError
from zentral.contrib.mdm.cert_issuer_backends.ident import IDent
from .utils import force_acme_issuer, force_scep_issuer


class MDMCertIssuerBackendsTestCase(TestCase):
    # CertIssuer backend

    def test_cert_issuer_backend_different_classes_eq_false(self):
        backend = force_scep_issuer().get_backend()
        self.assertNotEqual(backend, "YOLO")

    def test_cert_issuer_backend_different_instances_eq_false(self):
        backend = force_scep_issuer().get_backend()
        backend_2 = force_scep_issuer().get_backend()
        self.assertNotEqual(backend, backend_2)

    def test_base_class_update_acme_payload_not_implemented(self):
        issuer = force_scep_issuer()
        base_backend = CertIssuer(issuer, False)
        with self.assertRaises(NotImplementedError):
            base_backend.update_acme_payload({}, True, True, Mock())

    def test_base_class_update_scep_payload_not_implemented(self):
        issuer = force_scep_issuer()
        base_backend = CertIssuer(issuer, False)
        with self.assertRaises(NotImplementedError):
            base_backend.update_scep_payload({}, Mock())

    # IDent

    def test_ident_get_csr_config(self):
        self.assertEqual(
            IDent.get_csr_config(
                [[["CN", "CN"]],
                 [["O", "O1"]],
                 [["2.5.4.10", "O2"]],
                 [["2.5.4.11", "OU1"]],
                 [["OU", "OU2"]],
                 [["C", "C1"]],
                 [["2.5.4.6", "C2"]],
                 [["2.5.4.5", "SN"]]],
                {"rfc822Name": "EM1",
                 "dNSName": "DN1",
                 "ntPrincipalName": "NT1"},
                5
            ),
            {"subject": {
                "country": ["C1", "C2"],
                "organization": ["O1", "O2"],
                "organizational_unit": ["OU1", "OU2"],
                "serial_number": "SN",
                "common_name": "CN",
             },
             "subject_alternative_names": {
                "dns_names": ["DN1"],
                "email_addresses": ["EM1"],
                "nt_principal_names": ["NT1"],
             },
             "key_usage": 5}
        )

    @patch("zentral.contrib.mdm.cert_issuer_backends.ident.requests.Session")
    def test_ident_cert_issuer_error(self, requests_session):
        response = Mock()
        response.raise_for_status.side_effect = Exception("Boom!!!")
        session = Mock()
        session.post.return_value = response
        requests_session.return_value = session
        backend = force_acme_issuer(backend=CertIssuerBackend.IDent).get_backend(load=True)
        with self.assertRaises(CertIssuerError) as cm:
            backend.update_acme_payload({}, True, True, Mock())
        self.assertEqual(cm.exception.args[0], "Request error: Boom!!!")

    @patch("zentral.contrib.mdm.cert_issuer_backends.ident.requests.Session")
    def test_ident_update_acme_payload(self, requests_session):
        response = Mock()
        response.json.return_value = {"challenge": "YoloFomo"}
        session = Mock()
        session.post.return_value = response
        requests_session.return_value = session
        backend = force_acme_issuer(backend=CertIssuerBackend.IDent).get_backend(load=True)
        acme_payload = {"Subject": [[["CN", "Yolo"]]]}
        backend.update_acme_payload(acme_payload, True, True, Mock())
        self.assertEqual(backend.instance.usage_flags, 1)
        self.assertEqual(acme_payload["ClientIdentifier"], "YoloFomo")
        self.assertEqual(acme_payload["UsageFlags"], backend.instance.usage_flags)
        session.post.assert_called_once_with(
            backend.url,
            json={
                'subject': {'common_name': 'Yolo'},
                'key_usage': backend.instance.usage_flags
            }
        )

    @patch("zentral.contrib.mdm.cert_issuer_backends.ident.requests.Session")
    def test_ident_update_scep_payload(self, requests_session):
        response = Mock()
        response.json.return_value = {"challenge": "YoloFomo"}
        session = Mock()
        session.post.return_value = response
        requests_session.return_value = session
        backend = force_scep_issuer(backend=CertIssuerBackend.IDent).get_backend(load=True)
        scep_payload = {"Subject": [[["CN", "Yolo"]]]}
        backend.update_scep_payload(scep_payload, Mock())
        self.assertEqual(backend.instance.key_usage, 0)
        self.assertEqual(scep_payload["Challenge"], "YoloFomo")
        self.assertEqual(scep_payload["Key Usage"], backend.instance.key_usage)
        session.post.assert_called_once_with(
            backend.url,
            json={
                'subject': {'common_name': 'Yolo'},
                'key_usage': backend.instance.key_usage
            }
        )

    # StaticChallenge

    def test_static_challenge_update_acme_payload(self):
        backend = force_acme_issuer(backend=CertIssuerBackend.StaticChallenge).get_backend(load=True)
        acme_payload = {}
        backend.update_acme_payload(acme_payload, True, True, Mock())
        self.assertEqual(acme_payload["ClientIdentifier"], backend.challenge)

    # BaseMicrosoftCA - for uncovered lines elsewhere

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    def test_base_microsoft_ca_raise_for_status(self, requests_get):
        response = Mock()
        response.raise_for_status.side_effect = Exception("Boom!!!")
        requests_get.return_value = response
        backend = force_acme_issuer(backend=CertIssuerBackend.MicrosoftCA).get_backend(load=True)
        with self.assertRaises(CertIssuerError) as cm:
            backend.update_acme_payload({}, True, True, Mock())
        self.assertEqual(cm.exception.args[0], "Request error: Boom!!!")

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    def test_microsoft_ca_unicode_error(self, requests_get):
        response = Mock()
        response.content = b"\x01"
        requests_get.return_value = response
        backend = force_acme_issuer(backend=CertIssuerBackend.MicrosoftCA).get_backend(load=True)
        with self.assertRaises(CertIssuerError) as cm:
            backend.update_acme_payload({}, True, True, Mock())
        self.assertEqual(cm.exception.args[0], "Could not decode response.")

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    def test_okta_ca_no_match(self, requests_get):
        response = Mock()
        response.content = "no match!".encode("windows-1252")
        requests_get.return_value = response
        backend = force_acme_issuer(backend=CertIssuerBackend.OktaCA).get_backend(load=True)
        with self.assertRaises(CertIssuerError) as cm:
            backend.update_acme_payload({}, True, True, Mock())
        self.assertEqual(cm.exception.args[0], "Could not find challenge in response.")

    @patch("zentral.contrib.mdm.cert_issuer_backends.base_microsoft_ca.requests.get")
    def test_okta_ca_update_scep(self, requests_get):
        response = Mock()
        response.content = "challenge password is: <B> abc123 </B>".encode("windows-1252")
        requests_get.return_value = response
        backend = force_scep_issuer(backend=CertIssuerBackend.OktaCA).get_backend(load=True)
        scep_payload = {}
        backend.update_scep_payload(scep_payload, Mock())
        self.assertEqual(scep_payload["Challenge"], "abc123")
        self.assertEqual(scep_payload["Keysize"], backend.instance.key_size)
        self.assertEqual(scep_payload["Key Type"], "RSA")

    # get_cert_issuer_backend

    @patch("zentral.contrib.mdm.cert_issuer_backends.import_module")
    def test_get_cert_issuer_backend_import_error(self, import_module):
        import_module.side_effect = ImportError
        with self.assertRaises(ImportError):
            force_scep_issuer()

    # get_cached_cert_issuer_backend

    @patch("zentral.contrib.mdm.cert_issuer_backends.cert_issuer_cache")
    def test_get_cached_cert_issuer_backend_empty_cache(self, cert_issuer_cache):
        cert_issuer_cache.__getitem__.side_effect = KeyError
        scep_issuer = force_scep_issuer()
        backend = get_cached_cert_issuer_backend(scep_issuer)
        cert_issuer_cache.__setitem__.assert_called_once_with(
            scep_issuer.pk,
            (backend, 1)
        )

    @patch("zentral.contrib.mdm.cert_issuer_backends.cert_issuer_cache")
    def test_get_cached_cert_issuer_backend_older_version_in_cache(self, cert_issuer_cache):
        scep_issuer = force_scep_issuer()
        backend = scep_issuer.get_backend(load=True)
        scep_issuer.version = 2
        scep_issuer.save()
        scep_issuer.refresh_from_db()  # F() for version !
        cert_issuer_cache.__getitem__.return_value = (backend, 1)
        returned_backend = get_cached_cert_issuer_backend(scep_issuer)
        cert_issuer_cache.__setitem__.assert_called_once_with(
            scep_issuer.pk,
            (returned_backend, 2)
        )
        self.assertNotEqual(backend, returned_backend)  # different versions

    @patch("zentral.contrib.mdm.cert_issuer_backends.cert_issuer_cache")
    def test_get_cached_cert_issuer_backend_correct_version_in_cache(self, cert_issuer_cache):
        scep_issuer = force_scep_issuer()
        backend = scep_issuer.get_backend(load=True)
        cert_issuer_cache.__getitem__.return_value = (backend, 1)
        returned_backend = get_cached_cert_issuer_backend(scep_issuer)
        cert_issuer_cache.__setitem__.assert_not_called()
        self.assertEqual(backend, returned_backend)  # same versions

    # test_acme_payload

    def test_acme_payload_no_info(self):
        self.assertEqual(
            test_acme_payload(None, (0,), None),
            (False, False, False),
        )

    def test_acme_payload_macos_silicon_all_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.MACOS, (15, 6, 1), "Mac16,1"),
            (True, True, True),
        )

    def test_acme_payload_macos_all_not_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.MACOS, (13,), "Mac16,1"),
            (False, False, False),
        )

    def test_acme_payload_macos_t1_no_hardware_no_attest(self):
        self.assertEqual(
            test_acme_payload(Platform.MACOS, (13, 6, 1), "MacBookPro14,2"),
            (True, False, False),
        )

    def test_acme_payload_macos_t2_hardware_ok_no_attest(self):
        self.assertEqual(
            test_acme_payload(Platform.MACOS, (15, 6, 1), "MacBookPro15,1"),
            (True, True, False),
        )

    def test_acme_payload_ios_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.IOS, (18, 6, 2), "iPhone14,4"),
            (True, True, True),
        )

    def test_acme_payload_ios_not_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.IOS, (13, 2, 1), "iPhone14,4"),
            (False, False, False),
        )

    def test_acme_payload_ipados_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.IPADOS, (17, 2), "iPad13,17"),
            (True, True, True),
        )

    def test_acme_payload_ipados_not_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.IPADOS, (15, 2), "iPad13,17"),
            (False, False, False),
        )

    def test_acme_payload_tvos_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.TVOS, (16,), "AppleTV14,1"),
            (True, True, True),
        )

    def test_acme_payload_tvos_not_ok(self):
        self.assertEqual(
            test_acme_payload(Platform.TVOS, (15,), "AppleTV14,1"),
            (False, False, False),
        )
