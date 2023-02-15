import plistlib
from urllib.parse import urlparse
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.payloads import build_mdm_configuration_profile
from .utils import force_dep_enrollment_session


class TestMDMPayloads(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def test_build_mdm_configuration_profile_default(self):
        self.assertNotIn("mtls_proxy", settings["apps"]["zentral.contrib.mdm"])
        session, _, _ = force_dep_enrollment_session(self.mbu)
        config_profile = build_mdm_configuration_profile(session)
        _, profile_data = verify_signed_payload(config_profile)
        profile = plistlib.loads(profile_data)
        mdm_payload = None
        for payload in profile["PayloadContent"]:
            payload_type = payload["PayloadType"]
            if payload_type == "com.apple.mdm":
                mdm_payload = payload
                break
        self.assertNotIn("SignMessage", mdm_payload)
        self.assertEqual(urlparse(mdm_payload["ServerURL"]).netloc, settings["api"]["fqdn_mtls"])
        self.assertEqual(urlparse(mdm_payload["CheckInURL"]).netloc, settings["api"]["fqdn_mtls"])

    def test_build_mdm_configuration_profile_mtls_proxy_true(self):
        mdm_conf = settings._collection["apps"]._collection["zentral.contrib.mdm"]
        mdm_conf["mtls_proxy"] = True
        session, _, _ = force_dep_enrollment_session(self.mbu)
        config_profile = build_mdm_configuration_profile(session)
        _, profile_data = verify_signed_payload(config_profile)
        profile = plistlib.loads(profile_data)
        mdm_payload = None
        for payload in profile["PayloadContent"]:
            payload_type = payload["PayloadType"]
            if payload_type == "com.apple.mdm":
                mdm_payload = payload
                break
        self.assertNotIn("SignMessage", mdm_payload)
        self.assertEqual(urlparse(mdm_payload["ServerURL"]).netloc, settings["api"]["fqdn_mtls"])
        self.assertEqual(urlparse(mdm_payload["CheckInURL"]).netloc, settings["api"]["fqdn_mtls"])
        mdm_conf.pop("mtls_proxy")

    def test_build_mdm_configuration_profile_mtls_proxy_false(self):
        mdm_conf = settings._collection["apps"]._collection["zentral.contrib.mdm"]
        mdm_conf["mtls_proxy"] = False
        session, _, _ = force_dep_enrollment_session(self.mbu)
        config_profile = build_mdm_configuration_profile(session)
        _, profile_data = verify_signed_payload(config_profile)
        profile = plistlib.loads(profile_data)
        mdm_payload = None
        for payload in profile["PayloadContent"]:
            payload_type = payload["PayloadType"]
            if payload_type == "com.apple.mdm":
                mdm_payload = payload
                break
        self.assertTrue(mdm_payload["SignMessage"])
        self.assertEqual(urlparse(mdm_payload["ServerURL"]).netloc, settings["api"]["fqdn"])
        self.assertEqual(urlparse(mdm_payload["CheckInURL"]).netloc, settings["api"]["fqdn"])
        mdm_conf.pop("mtls_proxy")
