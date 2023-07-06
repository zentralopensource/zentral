import plistlib
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import RealmGroupMapping
from realms.utils import build_password_hash_dict, serialize_password_hash_dict, get_realm_user_mapped_groups
from .utils import force_realm_user


class RealmUtilsTestCase(TestCase):
    @patch("realms.utils.random.getrandbits")
    def test_build_password_hash_dict(self, getrandbits):
        getrandbits.return_value = 0
        self.assertEqual(
            build_password_hash_dict("yolofomo"),
            {
                "SALTED-SHA512-PBKDF2": {
                    "entropy": "gk+6qey048x1NausVGMKYw81gcIR2RNiCSeNujsAgY6Sbipd/7OlomEkZKfkGl3W1IN3epAC1qewQ94"
                    "TSCsIDCh/0gbi/vL0kTI5Llm1TuaxLyTgLDtVnOglA11KLSQhUXDncSb7y1CvrqCdvfopP7fvFmao3o"
                    "kpgxzeQ+VfWwg=",
                    "iterations": 39999,
                    "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                }
            },
        )

    def test_serialize_password_hash_dict(self):
        self.assertEqual(
            plistlib.loads(
                serialize_password_hash_dict(
                    {
                        "SALTED-SHA512-PBKDF2": {
                            "entropy": "gk+6qey048x1NausVGMKYw81gcIR2RNiCSeNujsAgY6Sbipd/7OlomEkZKfkGl3W1IN3epAC1qewQ9"
                            "4TSCsIDCh/0gbi/vL0kTI5Llm1TuaxLyTgLDtVnOglA11KLSQhUXDncSb7y1CvrqCdvfopP7fvFmao3o"
                            "kpgxzeQ+VfWwg=",
                            "iterations": 39999,
                            "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        }
                    }
                )
            ),
            {
                "SALTED-SHA512-PBKDF2": {
                    "entropy": b"\x82O\xba\xa9\xec\xb4\xe3\xccu5\xab\xac"
                    b"Tc\nc\x0f5\x81\xc2\x11\xd9\x13b"
                    b"\t'\x8d\xba;\x00\x81\x8e\x92n*]"
                    b"\xff\xb3\xa5\xa2a$d\xa7\xe4\x1a]\xd6"
                    b"\xd4\x83wz\x90\x02\xd6\xa7\xb0C\xde\x13"
                    b"H+\x08\x0c(\x7f\xd2\x06\xe2\xfe\xf2\xf4"
                    b"\x9129.Y\xb5N\xe6\xb1/$\xe0,;U\x9c"
                    b"\xe8%\x03]J-$!Qp\xe7q&\xfb\xcbP"
                    b"\xaf\xae\xa0\x9d\xbd\xfa)?\xb7\xef\x16f"
                    b"\xa8\xde\x89)\x83\x1c\xdeC\xe5_[\x08",
                    "iterations": 39999,
                    "salt": b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00",
                }
            },
        )

    def test_realm_user_mapped_groups_no_claims(self):
        realm, realm_user = force_realm_user()
        group = Group.objects.create(name=get_random_string(12))
        RealmGroupMapping.objects.create(
            realm=realm,
            claim="Yolo",
            separator="",
            value="Fomo",
            group=group,
        )
        self.assertEqual(len(get_realm_user_mapped_groups(realm_user)), 0)

    def test_realm_user_mapped_groups_no_list_no_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"Yolo": "Fomo",
                             "Un": 1}
        group = Group.objects.create(name=get_random_string(12))
        RealmGroupMapping.objects.create(
            realm=realm,
            claim="Un",
            separator="",
            value="1",
            group=group,
        )
        self.assertEqual(get_realm_user_mapped_groups(realm_user), {group})

    def test_realm_user_mapped_groups_ava_list_no_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo", "Un": [1]}}
        group = Group.objects.create(name=get_random_string(12))
        RealmGroupMapping.objects.create(
            realm=realm,
            claim="Un",
            separator="",
            value="1",
            group=group,
        )
        self.assertEqual(get_realm_user_mapped_groups(realm_user), {group})

    def test_realm_user_mapped_groups_ava_list_no_sep_no_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo1;Fomo2;Fomo3", "Un": [1]}}
        group = Group.objects.create(name=get_random_string(12))
        RealmGroupMapping.objects.create(
            realm=realm,
            claim="Yolo",
            separator="",
            value="Fomo2",
            group=group,
        )
        self.assertEqual(len(get_realm_user_mapped_groups(realm_user)), 0)

    def test_realm_user_mapped_groups_ava_list_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo1;Fomo2;Fomo3", "Un": [1]}}
        group = Group.objects.create(name=get_random_string(12))
        RealmGroupMapping.objects.create(
            realm=realm,
            claim="Yolo",
            separator=";",
            value="Fomo2",
            group=group,
        )
        self.assertEqual(get_realm_user_mapped_groups(realm_user), {group})
