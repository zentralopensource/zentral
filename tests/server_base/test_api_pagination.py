from django.contrib.auth.models import Group
from django.test import SimpleTestCase, TestCase
from django.urls import get_resolver, URLPattern, URLResolver
from django.utils.crypto import get_random_string
from rest_framework import generics, mixins
from rest_framework.generics import GenericAPIView
from rest_framework.viewsets import GenericViewSet

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase


# List endpoints whose queryset has no ordering. LIMIT/OFFSET over an unordered
# queryset lets a row move between pages, so a client walking the pages can see
# it twice and miss another one. Shrink this list, never grow it.
UNORDERED_LIST_ENDPOINTS = [
    "api/accounts/token_issuers/oidc/",
    "api/mdm/artifacts/",
    "api/mdm/cert_assets/",
    "api/mdm/data_assets/",
    "api/mdm/declarations/",
    "api/mdm/dep/virtual_servers/",
    "api/mdm/dep_enrollment_custom_views/",
    "api/mdm/devices/",
    "api/mdm/enrollment_custom_views/",
    "api/mdm/enterprise_apps/",
    "api/mdm/profiles/",
    "api/mdm/provisioning_profiles/",
    "api/mdm/store_apps/",
]


def iter_url_patterns(resolver, prefix=""):
    for url_pattern in resolver.url_patterns:
        pattern = prefix + str(url_pattern.pattern)
        if isinstance(url_pattern, URLResolver):
            yield from iter_url_patterns(url_pattern, pattern)
        elif isinstance(url_pattern, URLPattern):
            yield pattern, url_pattern.callback


def iter_api_list_views():
    for pattern, callback in iter_url_patterns(get_resolver()):
        if not pattern.startswith("api/"):
            continue
        view_class = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
        if view_class is None or not issubclass(view_class, (GenericAPIView, GenericViewSet)):
            continue
        actions = getattr(callback, "actions", None)
        if actions:
            # router generated viewset view, the method map tells us what it serves
            if "list" not in actions.values():
                continue
        elif not issubclass(view_class, (mixins.ListModelMixin, generics.ListAPIView)):
            continue
        yield pattern, view_class


class APIPaginationTestCase(SimpleTestCase):
    maxDiff = None

    def test_api_list_views_are_paginated(self):
        checked = 0
        unpaginated = []
        for pattern, view_class in sorted(iter_api_list_views(), key=lambda t: t[0]):
            checked += 1
            if view_class.pagination_class is None:
                unpaginated.append(f"{pattern} {view_class.__module__}.{view_class.__qualname__}")
        self.assertEqual(unpaginated, [])
        # a scan that finds nothing would pass without checking anything
        self.assertGreater(checked, 50)

    def test_api_list_view_querysets_are_ordered(self):
        checked = 0
        unordered = []
        for pattern, view_class in sorted(iter_api_list_views(), key=lambda t: t[0]):
            queryset = getattr(view_class, "queryset", None)
            if queryset is None:
                continue
            checked += 1
            if not queryset.query.order_by and not queryset.model._meta.ordering:
                unordered.append(pattern)
        self.assertEqual(unordered, UNORDERED_LIST_ENDPOINTS)
        self.assertGreater(checked, 50)


class APIListEnvelopeTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.com".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.service_account

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "base_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    def view_permissions(self, view_class):
        permissions = getattr(view_class, "permission_required", None)
        if permissions:
            if not isinstance(permissions, (list, tuple)):
                permissions = [permissions]
            return list(permissions)
        model = view_class.queryset.model
        return [f"{model._meta.app_label}.view_{model._meta.model_name}"]

    def test_api_list_views_answer_with_a_page(self):
        checked = 0
        for pattern, view_class in sorted(iter_api_list_views(), key=lambda t: t[0]):
            with self.subTest(pattern):
                self.set_permissions(*self.view_permissions(view_class))
                response = self.get(f"/{pattern}")
                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(set(payload), {"count", "next", "previous", "results"})
                self.assertIsInstance(payload["results"], list)
                # everything the test database holds fits on the first page
                self.assertEqual(payload["count"], len(payload["results"]))
                self.assertIsNone(payload["next"])
                self.assertIsNone(payload["previous"])
            checked += 1
        self.assertGreater(checked, 50)
