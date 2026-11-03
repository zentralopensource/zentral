from importlib import import_module

from django.apps import apps
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy
from pbac.engine import engine
from realms.pbac import ProvisionRealmRequest
from .utils import force_realm, force_user


migration = import_module("realms.migrations.0017_scim_provisioning_policies")


class SCIMProvisioningMigrationTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.scim_role = cls.force_role("view", "create", "update", "delete")
        # the SCIM permissions without the deletes
        cls.six_role = cls.force_role("view", "create", "update")
        # the SCIM permissions, and one more
        cls.broad_role = cls.force_role("view", "create", "update", "delete",
                                        extra='Realms::Action::"viewRealm"')
        cls.partial_role = cls.force_role("view")

    @staticmethod
    def force_role(*operations, extra=None):
        role = Group.objects.create(name=get_random_string(12))
        # the policy of the SCIM documentation before provisionRealm, as written in the console
        actions = [f'Realms::Action::"{operation}{model}"'
                   for model in ("RealmUser", "RealmGroup") for operation in operations]
        if extra:
            actions.append(extra)
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal in Role::"{role.pk}", action in [{", ".join(actions)}], resource);',
        )
        return role

    def force_scim_realm(self, name=None):
        realm = force_realm()
        realm.scim_enabled = True
        if name:
            realm.name = name
        realm.save()
        return realm

    def force_account(self, role, service_account=True, active=True):
        account = force_user(service_account=service_account, active=active)
        account.groups.set([role])
        return account

    def migrate(self):
        migration.give_provision_realm_to_the_scim_accounts(apps, None)

    def provision_realm(self, user, realm):
        user = type(user).objects.get(pk=user.pk)
        request = ProvisionRealmRequest(user, realm)
        engine.authorize_request(request)
        return request.is_authorized

    def test_no_scim_realm(self):
        force_realm()
        self.force_account(self.scim_role)
        group_count = Group.objects.count()
        policy_count = Policy.objects.count()
        self.migrate()
        self.assertEqual(Group.objects.count(), group_count)
        self.assertEqual(Policy.objects.count(), policy_count)

    def test_role_and_policies(self):
        realm1 = self.force_scim_realm()
        realm2 = self.force_scim_realm()
        no_scim_realm = force_realm()
        scim_account = self.force_account(self.scim_role)
        six_account = self.force_account(self.six_role)
        broad_account = self.force_account(self.broad_role)
        partial_account = self.force_account(self.partial_role)
        user = self.force_account(self.scim_role, service_account=False)
        self.force_account(self.scim_role, active=False)
        self.migrate()
        role = Group.objects.get(name="SCIM provisioning")
        self.assertEqual(list(role.user_set.all()), [scim_account])
        for realm in (realm1, realm2):
            policy = Policy.objects.get(name=f"SCIM provisioning: {realm.name}")
            self.assertEqual(
                policy.source,
                "permit (\n"
                f'  principal is ServiceAccount in Role::"{role.pk}",\n'
                '  action == Realms::Action::"provisionRealm",\n'
                f'  resource == Realms::Realm::"{realm.pk}"\n'
                ");"
            )
            # the historical model skips clean(), which validates the source against the schema
            policy.full_clean()
            self.assertTrue(policy.is_active)
            self.assertIsNone(policy.provisioning_uid)
            self.assertTrue(policy.description.startswith('Made by the upgrade to Realms::Action::"provisionRealm".'))
            self.assertTrue(self.provision_realm(scim_account, realm))
            for account in (six_account, broad_account, partial_account):
                self.assertFalse(self.provision_realm(account, realm))
        self.assertFalse(Policy.objects.filter(name__endswith=no_scim_realm.name).exists())
        self.assertFalse(self.provision_realm(scim_account, no_scim_realm))
        # a role mapping can give the role to a user: the type test refuses it
        user.groups.add(role)
        self.assertFalse(self.provision_realm(user, realm1))

    def test_policy_on_the_account(self):
        # the SCIM documentation before provisionRealm named the service account, with no role
        realm = self.force_scim_realm()
        account = force_user(service_account=True)
        actions = ", ".join(f'Realms::Action::"{operation}{model}"'
                            for model in ("RealmUser", "RealmGroup")
                            for operation in ("view", "create", "update", "delete"))
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == ServiceAccount::"{account.pk}", action in [{actions}], resource);',
        )
        self.migrate()
        role = Group.objects.get(name="SCIM provisioning")
        self.assertEqual(list(role.user_set.all()), [account])
        self.assertTrue(self.provision_realm(account, realm))

    def test_name_conflicts(self):
        realm1 = self.force_scim_realm(name=get_random_string(12))
        realm2 = self.force_scim_realm(name=realm1.name)
        Group.objects.create(name="SCIM provisioning")
        Policy.objects.create(name=f"SCIM provisioning: {realm1.name}",
                              source="permit (principal, action, resource) when { false };")
        self.migrate()
        role = Group.objects.get(name="SCIM provisioning (2)")
        self.assertEqual(
            {p.name: p.source.split('Realms::Realm::"')[1][:36]
             for p in Policy.objects.filter(source__contains=f'Role::"{role.pk}"')},
            {f"SCIM provisioning: {realm1.name} (2)": str(min(realm1.pk, realm2.pk)),
             f"SCIM provisioning: {realm1.name} (3)": str(max(realm1.pk, realm2.pk))}
        )
