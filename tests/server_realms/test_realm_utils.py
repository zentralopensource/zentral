from django.contrib.auth.models import Group
from django.http import HttpRequest
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User
from realms.models import RealmGroupMapping, RoleMapping
from realms.utils import (apply_realm_group_mappings, apply_role_mappings,
                          get_realm_user_mapped_groups, get_realm_user_mapped_realm_groups)
from .utils import force_realm_user, force_realm_group


class RealmUtilsTestCase(TestCase):

    # apply_role_mappings

    def test_apply_role_mapping_user_not_remote(self):
        realm_group = force_realm_group()
        _, realm_user = force_realm_user(realm=realm_group.realm, group=realm_group)
        user = User.objects.create_user(realm_user.username, realm_user.email, get_random_string(12))
        user.is_remote = False  # groups not updated if user is not remote
        self.assertEqual(user.groups.count(), 0)
        group = Group.objects.create(name=get_random_string(12))
        RoleMapping.objects.create(
            realm_group=realm_group,
            group=group,
        )
        request = HttpRequest()
        request.user = user
        apply_role_mappings(request, realm_user)
        self.assertEqual(user.groups.count(), 0)

    def test_apply_role_mapping(self):
        realm_group = force_realm_group()
        _, realm_user = force_realm_user(realm=realm_group.realm, group=realm_group)
        user = User.objects.create_user(realm_user.username, realm_user.email, get_random_string(12))
        user.is_remote = True  # groups updated if user is remote
        self.assertEqual(user.groups.count(), 0)
        group = Group.objects.create(name=get_random_string(12))
        RoleMapping.objects.create(
            realm_group=realm_group,
            group=group,
        )
        request = HttpRequest()
        request.user = user
        request.session = self.client.session  # for the events
        apply_role_mappings(request, realm_user)
        self.assertEqual(user.groups.count(), 1)
        self.assertEqual(user.groups.first(), group)

    # get_realm_user_mapped_groups

    def test_realm_user_mapped_groups_no_match(self):
        realm, realm_user = force_realm_user()
        realm_group = force_realm_group(realm=realm)
        group = Group.objects.create(name=get_random_string(12))
        RoleMapping.objects.create(
            realm_group=realm_group,
            group=group,
        )
        self.assertEqual(get_realm_user_mapped_groups(realm_user), set())

    def test_realm_user_mapped_groups_with_parent(self):
        parent_group = force_realm_group()
        child_group = force_realm_group(realm=parent_group.realm, parent=parent_group)
        group = Group.objects.create(name=get_random_string(12))
        _, realm_user = force_realm_user(realm=parent_group.realm, group=child_group)
        RoleMapping.objects.create(
            realm_group=parent_group,
            group=group,
        )
        self.assertEqual(get_realm_user_mapped_groups(realm_user), {group})

    # apply_realm_group_mappings

    def test_apply_realm_group_mappings_no_mappings(self):
        _, realm_user = force_realm_user()
        realm_group = force_realm_group(realm=realm_user.realm)
        realm_user.groups.add(realm_group)
        apply_realm_group_mappings(realm_user)
        self.assertEqual(realm_user.groups.count(), 1)
        self.assertEqual(realm_user.groups.first(), realm_group)

    def test_apply_realm_group_mappings_set_one(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"Yolo": "Fomo",
                             "Un": 1}
        realm_user.save()
        old_realm_group = force_realm_group(realm=realm)
        new_realm_group = force_realm_group(realm=realm)
        realm.scim_enabled = True
        scim_realm_group = force_realm_group(realm=realm)
        self.assertTrue(scim_realm_group.scim_managed is True)
        self.assertIsNotNone(scim_realm_group.scim_external_id)
        realm_user.groups.add(old_realm_group)  # this one will be removed
        realm_user.groups.add(scim_realm_group)  # this one should not be affected
        self.assertEqual(realm_user.groups.count(), 2)
        RealmGroupMapping.objects.create(
            claim="Un",
            separator="",
            value="1",
            realm_group=new_realm_group,
        )
        apply_realm_group_mappings(realm_user)
        self.assertEqual(realm_user.groups.count(), 2)
        self.assertEqual(set(realm_user.groups.all()), {new_realm_group, scim_realm_group})

    # get_realm_user_mapped_realm_groups

    def test_realm_user_mapped_realm_groups_no_mappings(self):
        _, realm_user = force_realm_user()
        self.assertIsNone(get_realm_user_mapped_realm_groups(realm_user))

    def test_realm_user_mapped_realm_groups_different_realm_no_mappings(self):
        _, realm_user = force_realm_user()
        realm_group = force_realm_group()
        self.assertNotEqual(realm_user.realm, realm_group.realm)
        RealmGroupMapping.objects.create(
            claim="Yolo",
            separator="",
            value="Fomo",
            realm_group=realm_group,
        )
        self.assertIsNone(get_realm_user_mapped_realm_groups(realm_user))

    def test_realm_user_mapped_realm_groups_no_claims(self):
        realm, realm_user = force_realm_user()
        realm_group = force_realm_group(realm=realm)
        RealmGroupMapping.objects.create(
            claim="Yolo",
            separator="",
            value="Fomo",
            realm_group=realm_group,
        )
        self.assertEqual(len(get_realm_user_mapped_realm_groups(realm_user)), 0)

    def test_realm_user_mapped_realm_groups_no_list_no_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"Yolo": "Fomo",
                             "Un": 1}
        realm_group = force_realm_group(realm=realm)
        RealmGroupMapping.objects.create(
            claim="Un",
            separator="",
            value="1",
            realm_group=realm_group,
        )
        self.assertEqual(get_realm_user_mapped_realm_groups(realm_user), {realm_group})

    def test_realm_user_mapped_realm_groups_ava_list_no_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo", "Un": [1]}}
        realm_group = force_realm_group(realm=realm)
        RealmGroupMapping.objects.create(
            claim="Un",
            separator="",
            value="1",
            realm_group=realm_group,
        )
        self.assertEqual(get_realm_user_mapped_realm_groups(realm_user), {realm_group})

    def test_realm_user_mapped_realm_groups_ava_list_no_sep_no_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo1;Fomo2;Fomo3", "Un": [1]}}
        realm_group = force_realm_group(realm=realm)
        RealmGroupMapping.objects.create(
            claim="Yolo",
            separator="",
            value="Fomo2",
            realm_group=realm_group,
        )
        self.assertEqual(len(get_realm_user_mapped_realm_groups(realm_user)), 0)

    def test_realm_user_mapped_realm_groups_ava_list_sep_one_match(self):
        realm, realm_user = force_realm_user()
        realm_user.claims = {"ava": {"Yolo": "Fomo1;Fomo2;Fomo3", "Un": [1]}}
        realm_group = force_realm_group(realm=realm)
        RealmGroupMapping.objects.create(
            claim="Yolo",
            separator=";",
            value="Fomo2",
            realm_group=realm_group,
        )
        self.assertEqual(get_realm_user_mapped_realm_groups(realm_user), {realm_group})
