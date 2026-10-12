from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.monolith.pbac import ViewPkgInfoDataRequest

from .utils import force_catalog, force_pkg_info, force_repository


class MonolithPBACTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.repository = force_repository(mbu=cls.mbu)
        cls.catalog = force_catalog(repository=cls.repository, name="testing")
        cls.other_catalog = force_catalog(repository=cls.repository, name="production")
        cls.pkg_info = force_pkg_info(catalog=cls.catalog)

    def _build_request(self, pkg_info=None, catalogs=None, user=None):
        pkg_info = pkg_info or self.pkg_info
        return ViewPkgInfoDataRequest(
            user or self.user,
            pkg_info,
            catalogs if catalogs is not None else pkg_info.active_catalogs(),
        )

    def _build_policy_source(self, scope="resource", forbidden_scope=None):
        source = ("permit ("
                  f' principal in Role::"{self.group.pk}",'
                  ' action == Monolith::Action::"viewPkgInfoData",'
                  f" {scope}"
                  ");\n")
        if forbidden_scope:
            source += ("forbid ("
                       " principal,"
                       ' action == Monolith::Action::"viewPkgInfoData",'
                       f" {forbidden_scope}"
                       ");\n")
        return source

    def _set_policy(self, scope="resource", forbidden_scope=None):
        Policy.objects.update_or_create(
            name="Monolith tests",
            defaults={"source": self._build_policy_source(scope, forbidden_scope)}
        )

    def _authorize(self, request):
        engine.authorize_request(request)
        return request.is_authorized

    # resource

    def test_view_pkg_info_data_request(self):
        self.pkg_info.catalogs.add(self.other_catalog)
        request = self._build_request()
        self.assertEqual(str(request.action), 'Monolith::Action::"viewPkgInfoData"')
        self.assertEqual(request.resource.full_type, "Monolith::PkgInfo")
        self.assertEqual(request.resource.id, str(self.pkg_info.pk))
        self.assertEqual(request.context, {})
        self.assertEqual(
            sorted(str(p) for p in request.resource.parents),
            sorted([f'Monolith::Repository::"{self.repository.pk}"',
                    f'Monolith::Catalog::"{self.catalog.pk}"',
                    f'Monolith::Catalog::"{self.other_catalog.pk}"'])
        )

    def test_view_pkg_info_data_request_repository_parent_meta_business_unit(self):
        request = self._build_request()
        repository_resource = next(p for p in request.resource.parents if p.type == "Repository")
        self.assertEqual([str(p) for p in repository_resource.parents],
                         [f'Inventory::MetaBusinessUnit::"{self.mbu.pk}"'])

    def test_view_pkg_info_data_request_repository_without_meta_business_unit(self):
        pkg_info = force_pkg_info()
        request = self._build_request(pkg_info=pkg_info)
        repository_resource = next(p for p in request.resource.parents if p.type == "Repository")
        self.assertEqual(repository_resource.parents, [])

    def test_view_pkg_info_data_request_without_catalog(self):
        self.pkg_info.catalogs.clear()
        request = self._build_request()
        self.assertEqual([str(p) for p in request.resource.parents],
                         [f'Monolith::Repository::"{self.repository.pk}"'])

    # decisions

    def test_view_pkg_info_data_request_denied_by_default(self):
        self.assertFalse(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_superuser_authorized(self):
        superuser = User.objects.create_user(
            get_random_string(12), "superuser@zentral.io", get_random_string(12),
            is_superuser=True,
        )
        self.assertTrue(self._build_request(user=superuser).is_authorized)

    def test_view_pkg_info_data_request_policy_authorized(self):
        self._set_policy()
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_pkg_info_authorized(self):
        self._set_policy(scope=f'resource == Monolith::PkgInfo::"{self.pkg_info.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_other_pkg_info_denied(self):
        self._set_policy(scope=f'resource == Monolith::PkgInfo::"{self.pkg_info.pk}"')
        other_pkg_info = force_pkg_info(catalog=self.catalog)
        self.assertFalse(self._authorize(self._build_request(pkg_info=other_pkg_info)))

    def test_view_pkg_info_data_request_policy_catalog_authorized(self):
        self._set_policy(scope=f'resource in Monolith::Catalog::"{self.catalog.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_other_catalog_denied(self):
        self._set_policy(scope=f'resource in Monolith::Catalog::"{self.other_catalog.pk}"')
        self.assertFalse(self._authorize(self._build_request()))

    # a scope on a catalog is existential: a pkginfo of the testing and of the production
    # catalog matches a policy scoped on testing

    def test_view_pkg_info_data_request_policy_catalog_authorized_extra_catalog(self):
        self.pkg_info.catalogs.add(self.other_catalog)
        self._set_policy(scope=f'resource in Monolith::Catalog::"{self.catalog.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_forbidden_catalog_denied(self):
        self.pkg_info.catalogs.add(self.other_catalog)
        self._set_policy(scope=f'resource in Monolith::Repository::"{self.repository.pk}"',
                         forbidden_scope=f'resource in Monolith::Catalog::"{self.other_catalog.pk}"')
        self.assertFalse(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_forbidden_catalog_other_pkg_info_authorized(self):
        self._set_policy(scope=f'resource in Monolith::Repository::"{self.repository.pk}"',
                         forbidden_scope=f'resource in Monolith::Catalog::"{self.other_catalog.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    # the repository is reachable from the pkginfo, and from its catalogs

    def test_view_pkg_info_data_request_policy_repository_authorized(self):
        self._set_policy(scope=f'resource in Monolith::Repository::"{self.repository.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_other_repository_denied(self):
        self._set_policy(scope=f'resource in Monolith::Repository::"{force_repository().pk}"')
        self.assertFalse(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_meta_business_unit_authorized(self):
        self._set_policy(scope=f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}"')
        self.assertTrue(self._authorize(self._build_request()))

    def test_view_pkg_info_data_request_policy_other_meta_business_unit_denied(self):
        other_mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        self._set_policy(scope=f'resource in Inventory::MetaBusinessUnit::"{other_mbu.pk}"')
        self.assertFalse(self._authorize(self._build_request()))

    def test_view_pkg_info_data_requests_batch_authorized(self):
        other_pkg_info = force_pkg_info(catalog=self.other_catalog)
        self._set_policy(scope=f'resource in Monolith::Catalog::"{self.catalog.pk}"')
        requests = [self._build_request(), self._build_request(pkg_info=other_pkg_info)]
        engine.authorize_requests(requests)
        self.assertTrue(requests[0].is_authorized)
        self.assertFalse(requests[1].is_authorized)

    # every scope must pass the schema validation Policy.clean runs, otherwise the action
    # would be unreachable for an operator

    def test_scoped_policies_are_valid(self):
        for scope in (f'resource == Monolith::PkgInfo::"{self.pkg_info.pk}"',
                      f'resource in Monolith::Catalog::"{self.catalog.pk}"',
                      f'resource in Monolith::Repository::"{self.repository.pk}"',
                      f'resource in Inventory::MetaBusinessUnit::"{self.mbu.pk}"'):
            with self.subTest(scope=scope):
                policy = Policy(name=get_random_string(12), source=self._build_policy_source(scope=scope))
                policy.full_clean()

    def test_system_scoped_policy_is_invalid(self):
        policy = Policy(name=get_random_string(12),
                        source=self._build_policy_source(scope='resource == System::"any"'))
        with self.assertRaises(ValidationError):
            policy.full_clean()

    def test_service_account_principal_policy_is_invalid(self):
        source = ('permit ('
                  ' principal == ServiceAccount::"1",'
                  ' action == Monolith::Action::"viewPkgInfoData",'
                  ' resource'
                  ');\n')
        policy = Policy(name=get_random_string(12), source=source)
        with self.assertRaises(ValidationError):
            policy.full_clean()
