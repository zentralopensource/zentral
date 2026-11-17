import itertools
from urllib.parse import parse_qs, urlparse

from django.contrib.auth.mixins import AccessMixin
from django.shortcuts import resolve_url
from django.conf import settings
from django.test import TestCase
from django.urls import NoReverseMatch, reverse
from django.urls.converters import IntConverter, UUIDConverter
from django.urls.resolvers import RoutePattern

from base.utils import iter_url_patterns
from zentral.contrib.osquery.models import Query


EXEMPT_PREFIXES = ("public/", "api/", "metrics/")

# the views outside the exempt prefixes that an anonymous client can reach
KNOWN_VIEWS_WITHOUT_ACCESS_MIXIN = {
    "accounts:nginx_auth_request",
    "accounts:verify_totp",
    "accounts:verify_webauthn",
    "base:health_check",
    "jamf:post_event",
    "login",
    "logout",
    "password_change",
    "password_change_done",
    "password_reset",
    "password_reset_complete",
    "password_reset_confirm",
    "password_reset_done",
    "puppet:post_report",
    "wsone:event_notifications",
}

REGEX_KWARG_CANDIDATES = ("999999", "inventory", "x")


def iter_console_url_patterns():
    for route, name, pattern in iter_url_patterns():
        route = route.lstrip("^")
        if route.startswith(EXEMPT_PREFIXES) or route.startswith("static_debug/"):
            continue
        yield route, name, pattern


def build_path(name, pattern):
    if isinstance(pattern.pattern, RoutePattern):
        kwargs = {}
        for kwarg, converter in pattern.pattern.converters.items():
            if isinstance(converter, IntConverter):
                kwargs[kwarg] = 999999
            elif isinstance(converter, UUIDConverter):
                kwargs[kwarg] = "00000000-0000-0000-0000-000000000000"
            else:
                kwargs[kwarg] = "x"
        return reverse(name, kwargs=kwargs)
    kwarg_names = list(pattern.pattern.regex.groupindex)
    for values in itertools.product(REGEX_KWARG_CANDIDATES, repeat=len(kwarg_names)):
        try:
            return reverse(name, kwargs=dict(zip(kwarg_names, values)))
        except NoReverseMatch:
            continue
    raise NoReverseMatch(name)


class AccessMixinLoginMiddlewareTestCase(TestCase):
    maxDiff = None

    @staticmethod
    def login_redirect_error(response, path):
        if response.status_code != 302:
            return f"status {response.status_code}"
        location = urlparse(response["Location"])
        if location.path != resolve_url(settings.LOGIN_URL):
            return f"location {response['Location']}"
        if parse_qs(location.query).get("next") != [path]:
            return f"next {response['Location']}"

    def assertLoginRedirect(self, response, path):
        self.assertIsNone(self.login_redirect_error(response, path))

    def test_console_views_have_an_access_mixin(self):
        unknown = []
        seen_known = set()
        for route, name, pattern in iter_console_url_patterns():
            view_class = getattr(pattern.callback, "view_class", None)
            if view_class is not None and issubclass(view_class, AccessMixin):
                continue
            if name in KNOWN_VIEWS_WITHOUT_ACCESS_MIXIN:
                seen_known.add(name)
                continue
            unknown.append(f"{route} {name}")
        self.assertEqual(unknown, [])
        self.assertEqual(seen_known, KNOWN_VIEWS_WITHOUT_ACCESS_MIXIN)

    def test_anonymous_requests_to_console_views_redirect_to_login(self):
        self.client.raise_request_exception = False
        checked = 0
        not_redirected = []
        for route, name, pattern in iter_console_url_patterns():
            view_class = getattr(pattern.callback, "view_class", None)
            if view_class is None or not issubclass(view_class, AccessMixin):
                continue
            self.assertIsNotNone(name, f"{route} has no name")
            path = build_path(name, pattern)
            for method in ("get", "post"):
                response = getattr(self.client, method)(path)
                checked += 1
                error = self.login_redirect_error(response, path)
                if error:
                    not_redirected.append(f"{method.upper()} {path} {error}")
        self.assertEqual(not_redirected, [])
        # a walk that finds nothing would pass without checking anything
        self.assertGreater(checked, 800)

    def test_anonymous_lookup_before_dispatch_known_and_unknown_object(self):
        query = Query.objects.create(name="query", sql="SELECT 1 FROM processes;")
        url = reverse("osquery:create_distributed_query")
        for query_string in (f"?q={query.pk}", "?q=999999", "?q=abc", ""):
            response = self.client.get(url + query_string)
            self.assertLoginRedirect(response, url + query_string)

    def test_views_without_access_mixin_are_not_redirected(self):
        self.assertEqual(self.client.get(reverse("base:health_check")).status_code, 200)
        self.assertEqual(self.client.get(reverse("accounts:nginx_auth_request")).status_code, 401)
