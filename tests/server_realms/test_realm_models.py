from django.test import TestCase
from .utils import force_realm, force_realm_group


class RealmModelsTestCase(TestCase):
    maxDiff = None

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
             'created_at': realm.created_at,
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
             'updated_at': realm.updated_at,
             'username_claim': 'username'}
        )

    def test_realm_group_serialize_for_event(self):
        parent_realm_group = force_realm_group()
        realm_group = force_realm_group(realm=parent_realm_group.realm, parent=parent_realm_group)
        self.assertEqual(
            realm_group.serialize_for_event(),
            {'created_at': realm_group.created_at,
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
             'updated_at': realm_group.updated_at}
        )
