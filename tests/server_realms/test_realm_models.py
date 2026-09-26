from django.test import TestCase
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from zentral.core.secret_engines import secret_engines
from .utils import force_realm, force_realm_group, force_realm_user


class RealmModelsTestCase(TestCase, SerializeForEventAssertions):
    maxDiff = None

    def setUp(self):
        # reset the secret engines to the default noop engine,
        # to be able to assert the tokens stored at rest
        secret_engines.load_config({})

    def test_serialize_for_event_is_json_native(self):
        realm = force_realm()
        for obj in (realm, force_realm_group(realm=realm)):
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
             'backend_kwargs': {
                 'bind_dn': 'uid=zentral,ou=Users,o=yolo,dc=example,dc=com',
                 'bind_password_hash': '311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02',
                 'host': 'ldap.example.com',
                 'users_base_dn': 'ou=Users,o=yolo,dc=example,dc=com'
             },
             'created_at': realm.created_at.isoformat(),
             'custom_attr_1_claim': '',
             'custom_attr_2_claim': '',
             'description': '',
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

    def test_realm_ldap_secrets_encrypted_at_rest(self):
        realm = force_realm()
        self.assertEqual(realm.backend_kwargs["bind_password"], "noop$eW9sbw==")
        self.assertEqual(
            realm.get_backend_kwargs(),
            {"host": "ldap.example.com",
             "bind_dn": "uid=zentral,ou=Users,o=yolo,dc=example,dc=com",
             "bind_password": "yolo",
             "users_base_dn": "ou=Users,o=yolo,dc=example,dc=com"}
        )

    def test_realm_openidc_secrets_encrypted_at_rest(self):
        realm = force_realm(backend="openidc")
        self.assertEqual(realm.backend_kwargs["client_secret"], "noop$Zm9tbw==")
        self.assertEqual(realm.get_backend_kwargs()["client_secret"], "fomo")

    def test_realm_saml_backend_kwargs_not_encrypted(self):
        realm = force_realm(backend="saml")
        self.assertEqual(
            realm.backend_kwargs,
            {"default_relay_state": "29eb0205-3572-4901-b773-fc82bef847ef",
             "idp_metadata": "<md></md>"}
        )

    def test_realm_rewrap_secrets(self):
        realm = force_realm()
        realm.rewrap_secrets()
        self.assertEqual(realm.backend_kwargs["bind_password"], "noop$eW9sbw==")
        self.assertEqual(realm.get_backend_kwargs()["bind_password"], "yolo")

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
