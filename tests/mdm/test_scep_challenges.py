from unittest.mock import patch, Mock
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.models import SCEPConfig
from zentral.contrib.mdm.scep import load_scep_challenge
from zentral.contrib.mdm.scep.base import SCEPChallengeError


class SCEPChallengeTestCase(TestCase):
    def build_scep_config(self, challenge_type, **kwargs):
        scep_config = SCEPConfig(
            name=get_random_string(12),
            url="https://example.com/{}".format(get_random_string(12)),
            challenge_type=challenge_type,
        )
        scep_config.set_challenge_kwargs(kwargs)
        scep_config.save()
        return scep_config

    def build_scep_challenge(self, challenge_type, **kwargs):
        return load_scep_challenge(self.build_scep_config(challenge_type, **kwargs))

    def test_static_scep_challenge(self):
        c = self.build_scep_challenge("STATIC", challenge="password1234")
        self.assertEqual(c.get(1, "yolo", "fomo"), "password1234")

    def test_static_scep_challenge_missing_challenge(self):
        scep_config = self.build_scep_config("STATIC", not_a_valid_key="password1234")
        with self.assertRaises(SCEPChallengeError) as cm:
            load_scep_challenge(scep_config)
        self.assertEqual(cm.exception.args[0],
                         f"'challenge' key missing from Static SCEP challenge kwargs {scep_config.pk}")

    def test_static_scep_challenge_empty_challenge(self):
        scep_config = self.build_scep_config("STATIC", challenge="")
        with self.assertRaises(SCEPChallengeError) as cm:
            load_scep_challenge(scep_config)
        self.assertEqual(cm.exception.args[0],
                         f"'challenge' key empty in Static SCEP challenge kwargs {scep_config.pk}")

    def test_unknown_challenge_type(self):
        with self.assertRaises(ValueError) as cm:
            self.build_scep_config("YOLO")
        self.assertEqual(cm.exception.args[0], "Unknown challenge type: YOLO")

    @patch("zentral.contrib.mdm.scep.microsoft_ca.requests.get")
    def test_microsoft_ca_scep_challenge(self, requests_get):
        challenge = get_random_string(16, allowed_chars="ABCDEF")
        resp = Mock()
        resp.content = f"challenge password is: <B> {challenge} </B>".encode("utf-16")
        requests_get.return_value = resp
        c = self.build_scep_challenge(
            "MICROSOFT_CA",
            url="https://example.com/{}".format(get_random_string(12)),
            username="yolo",
            password="fomo"
        )
        self.assertEqual(c.get(1, "yolo", "fomo"), challenge)

    @patch("zentral.contrib.mdm.scep.microsoft_ca.requests.get")
    def test_microsoft_ca_scep_challenge_server_error(self, requests_get):
        requests_get.side_effect = ValueError("fomo!")
        c = self.build_scep_challenge(
            "MICROSOFT_CA",
            url="https://example.com/{}".format(get_random_string(12)),
            username="yolo",
            password="fomo"
        )
        with self.assertRaises(SCEPChallengeError) as cm:
            c.get(1, "yolo", "fomo")
        self.assertEqual(cm.exception.args[0], "Request error: fomo!")

    @patch("zentral.contrib.mdm.scep.microsoft_ca.requests.get")
    def test_microsoft_ca_scep_challenge_unicode_error(self, requests_get):
        resp = Mock()
        resp.content = b"\x01\x02\x03\x04\x05"
        requests_get.return_value = resp
        c = self.build_scep_challenge(
            "MICROSOFT_CA",
            url="https://example.com/{}".format(get_random_string(12)),
            username="yolo",
            password="fomo"
        )
        with self.assertRaises(SCEPChallengeError) as cm:
            c.get(1, "yolo", "fomo")
        self.assertEqual(cm.exception.args[0], "Could not decode response.")

    @patch("zentral.contrib.mdm.scep.microsoft_ca.requests.get")
    def test_microsoft_ca_scep_challenge_could_not_find_challenge(self, requests_get):
        challenge = get_random_string(15, allowed_chars="ABCDEF")  # too short
        resp = Mock()
        resp.content = f"challenge password is: <B> {challenge} </B>".encode("utf-16")
        requests_get.return_value = resp
        c = self.build_scep_challenge(
            "MICROSOFT_CA",
            url="https://example.com/{}".format(get_random_string(12)),
            username="yolo",
            password="fomo"
        )
        with self.assertRaises(SCEPChallengeError) as cm:
            c.get(1, "yolo", "fomo")
        self.assertEqual(cm.exception.args[0], "Could not find challenge in response.")

    @patch("zentral.contrib.mdm.scep.microsoft_ca.requests.get")
    def test_okta_ca_scep_challenge(self, requests_get):
        challenge = get_random_string(40, allowed_chars="abcdef_-0123")
        resp = Mock()
        resp.content = f"challenge password is: <B> {challenge} </B>".encode("windows-1252")
        requests_get.return_value = resp
        c = self.build_scep_challenge(
            "OKTA_CA",
            url="https://example.com/{}".format(get_random_string(12)),
            username="yolo",
            password="fomo"
        )
        self.assertEqual(c.get(1, "yolo", "fomo"), challenge)
