from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import RealmGroupMapping
from realms.utils import get_realm_user_mapped_groups
from .utils import force_realm_user


class RealmUtilsTestCase(TestCase):
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
