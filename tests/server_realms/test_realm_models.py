from django.test import TestCase
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from realms.models import RealmUserGroupMembership, RoleMapping
from .utils import (force_group, force_realm, force_realm_group, force_realm_group_mapping, force_realm_user,
                    force_role_mapping)


class RealmModelsTestCase(TestCase, SerializeForEventAssertions):
    maxDiff = None

    def test_serialize_for_event_is_json_native(self):
        realm = force_realm()
        realm_group = force_realm_group(realm=realm)
        _, realm_user = force_realm_user(realm=realm, group=realm_group)
        for obj in (realm, realm_group,
                    RealmUserGroupMembership.objects.get(user=realm_user, group=realm_group),
                    force_realm_group_mapping(realm_group=realm_group),
                    force_role_mapping(realm=realm)):
            with self.subTest(obj._meta.model_name):
                self.assert_serialize_for_event_is_json_native(obj)

    def test_realm_iter_user_claim_mappings(self):
        realm = force_realm()
        self.assertEqual(
            list(realm.iter_user_claim_mappings()),
            [('username', 'username'),
             ('email', 'email'),
             ('first_name', ''),
             ('last_name', ''),
             ('full_name', ''),
             ('custom_attr_1', ''),
             ('custom_attr_2', '')]
        )

    def test_realm_serialize_for_event(self):
        realm = force_realm()
        self.assertEqual(
            realm.serialize_for_event(),
            {'backend': 'ldap',
             'config': {
                 'bind_dn': 'uid=zentral,ou=Users,o=yolo,dc=example,dc=com',
                 'bind_password': 'yolo',
                 'host': 'ldap.example.com',
                 'users_base_dn': 'ou=Users,o=yolo,dc=example,dc=com'
             },
             'created_at': realm.created_at.isoformat(),
             'custom_attr_1_claim': '',
             'custom_attr_2_claim': '',
             'email_claim': 'email',
             'enabled_for_login': False,
             'first_name_claim': '',
             'full_name_claim': '',
             'last_name_claim': '',
             'login_session_expiry': 0,
             'name': realm.name,
             'pk': str(realm.pk),
             'scim_enabled': False,
             'updated_at': realm.updated_at.isoformat(),
             'username_claim': 'username'}
        )

    def test_realm_group_serialize_for_event(self):
        parent_realm_group = force_realm_group()
        realm_group = force_realm_group(realm=parent_realm_group.realm, parent=parent_realm_group)
        self.assertEqual(
            realm_group.serialize_for_event(),
            {'created_at': realm_group.created_at.isoformat(),
             'display_name': realm_group.display_name,
             'parent': {'display_name': parent_realm_group.display_name,
                        'pk': str(parent_realm_group.pk),
                        'realm': {
                            'name': realm_group.realm.name,
                            'pk': str(realm_group.realm.pk),
                        }},
             'pk': str(realm_group.pk),
             'realm': {'name': realm_group.realm.name,
                       'pk': str(realm_group.realm.pk)},
             'scim_external_id': None,
             'updated_at': realm_group.updated_at.isoformat()}
        )

    def test_realm_group_mapped_roles(self):
        parent_realm_group = force_realm_group()
        realm_group = force_realm_group(realm=parent_realm_group.realm, parent=parent_realm_group)
        # a loop in the parents
        parent_realm_group.parent = realm_group
        parent_realm_group.save()
        parent_role = force_group()
        role = force_group()
        RoleMapping.objects.create(realm_group=parent_realm_group, group=parent_role)
        RoleMapping.objects.create(realm_group=realm_group, group=parent_role)
        RoleMapping.objects.create(realm_group=realm_group, group=role)
        mapped_roles = list(realm_group.mapped_roles())
        self.assertEqual(len(mapped_roles), 2)
        self.assertEqual(set(mapped_roles), {parent_role, role})
        self.assertEqual(list(force_realm_group().mapped_roles()), [])

    def test_realm_user_serialize_for_event_keys_only(self):
        realm, realm_user = force_realm_user()
        self.assertEqual(
            realm_user.serialize_for_event(keys_only=True),
            {'pk': str(realm_user.pk),
             'realm': {'name': realm.name,
                       'pk': str(realm.pk)},
             'username': realm_user.username}
        )

    def test_realm_user_serialize_for_event(self):
        realm, realm_user = force_realm_user()
        self.assertEqual(
            realm_user.serialize_for_event(),
            {'pk': str(realm_user.pk),
             'realm': {'name': realm.name,
                       'pk': str(realm.pk)},
             'username': realm_user.username,
             'email': realm_user.email,
             'first_name': realm_user.first_name,
             'last_name': realm_user.last_name}
        )

    def test_realm_user_group_membership_serialize_for_event_keys_only(self):
        realm_group = force_realm_group()
        _, realm_user = force_realm_user(realm=realm_group.realm, group=realm_group)
        membership = RealmUserGroupMembership.objects.get(user=realm_user, group=realm_group)
        self.assertEqual(
            membership.serialize_for_event(keys_only=True),
            {"pk": membership.pk,
             "realm_user": realm_user.serialize_for_event(keys_only=True),
             "realm_group": realm_group.serialize_for_event(keys_only=True)}
        )

    def test_realm_group_mapping_serialize_for_event_keys_only(self):
        rgm = force_realm_group_mapping()
        self.assertEqual(
            rgm.serialize_for_event(keys_only=True),
            {"pk": str(rgm.pk),
             "claim": rgm.claim,
             "separator": rgm.separator,
             "value": rgm.value,
             "realm_group": rgm.realm_group.serialize_for_event(keys_only=True)}
        )

    def test_role_mapping_serialize_for_event_keys_only(self):
        rm = force_role_mapping()
        self.assertEqual(
            rm.serialize_for_event(keys_only=True),
            {"pk": str(rm.pk),
             "realm_group": rm.realm_group.serialize_for_event(keys_only=True),
             "role": {"pk": rm.group.pk, "name": rm.group.name}}
        )
