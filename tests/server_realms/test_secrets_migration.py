from datetime import timedelta
from importlib import import_module

from django.apps import apps
from django.db import connection
from django.test import TestCase
from django.utils.crypto import get_random_string

from realms.models import Realm
from zentral.core.secret_engines import secret_engines
from zentral.utils.time import naive_utcnow

migration_module = import_module("realms.migrations.0016_realm_backend_kwargs")


class RealmBackendKwargsMigrationTestCase(TestCase):
    def setUp(self):
        # reset the secret engines to the default noop engine,
        # to be able to assert the tokens stored at rest
        secret_engines.load_config({})

    def _force_realm(self, backend, backend_kwargs):
        return Realm.objects.create(
            name=get_random_string(12),
            backend=backend,
            backend_kwargs=backend_kwargs,
            username_claim="username",
        )

    def test_encrypt_realm_secrets(self):
        ldap_realm = self._force_realm(
            "ldap",
            {"host": "ldap.example.com",
             "bind_dn": "uid=zentral,ou=Users,o=yolo,dc=example,dc=com",
             "bind_password": "yolo",
             "users_base_dn": "ou=Users,o=yolo,dc=example,dc=com"},
        )
        openidc_realm = self._force_realm(
            "openidc",
            {"discovery_url": "https://zentral.example.com/.well-known/openid-configuration",
             "client_id": "yolo",
             "client_secret": "fomo",
             "extra_scopes": []},
        )
        openidc_pkce_realm = self._force_realm(
            "openidc",
            {"discovery_url": "https://zentral.example.com/.well-known/openid-configuration",
             "client_id": "yolo",
             "extra_scopes": []},
        )
        saml_realm = self._force_realm("saml", {"idp_metadata": "<md></md>"})
        migration_module.encrypt_realm_secrets(apps, None)
        for realm in (ldap_realm, openidc_realm, openidc_pkce_realm, saml_realm):
            realm.refresh_from_db()
        self.assertEqual(ldap_realm.backend_kwargs["bind_password"], "noop$eW9sbw==")
        self.assertEqual(ldap_realm.get_backend_kwargs()["bind_password"], "yolo")
        self.assertEqual(openidc_realm.backend_kwargs["client_secret"], "noop$Zm9tbw==")
        self.assertEqual(openidc_realm.get_backend_kwargs()["client_secret"], "fomo")
        self.assertNotIn("client_secret", openidc_pkce_realm.backend_kwargs)
        self.assertEqual(saml_realm.backend_kwargs, {"idp_metadata": "<md></md>"})

    def _drop_name_unique_constraint(self):
        # simulate the pre-migration schema, where realm names were not unique.
        # rolled back with the test transaction.
        table = Realm._meta.db_table
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(cursor, table)
            for constraint_name, constraint in constraints.items():
                if constraint["columns"] == ["name"] and constraint["unique"]:
                    cursor.execute(f'ALTER TABLE "{table}" DROP CONSTRAINT "{constraint_name}"')

    def test_dedupe_realm_names(self):
        self._drop_name_unique_constraint()
        realms = [self._force_realm("ldap", {}) for _ in range(3)]
        for realm, name, age in zip(realms, ("Yolo", "Yolo (2)", "Yolo"), (2, 1, 0)):
            Realm.objects.filter(pk=realm.pk).update(name=name, created_at=naive_utcnow() - timedelta(days=age))
        migration_module.dedupe_realm_names(apps, None)
        for realm in realms:
            realm.refresh_from_db()
        self.assertEqual(realms[0].name, "Yolo")
        self.assertEqual(realms[1].name, "Yolo (2)")
        self.assertEqual(realms[2].name, "Yolo (3)")
