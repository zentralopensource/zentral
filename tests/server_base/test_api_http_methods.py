from django.test import SimpleTestCase
from django.urls import URLPattern, URLResolver, get_resolver
from rest_framework.views import APIView


def iter_api_views(resolver=None, prefix=""):
    if resolver is None:
        resolver = get_resolver()
    for pattern in resolver.url_patterns:
        path = prefix + str(pattern.pattern)
        if isinstance(pattern, URLResolver):
            yield from iter_api_views(pattern, path)
        elif isinstance(pattern, URLPattern):
            view_class = getattr(pattern.callback, "cls", None)
            if view_class is not None and issubclass(view_class, APIView):
                yield path, view_class


class APIHTTPMethodsTestCase(SimpleTestCase):
    maxDiff = None

    def test_the_traversal_reaches_the_api(self):
        """A guard that stops traversing passes for the wrong reason.

        The counts are lower bounds on an API that only grows; they exist so that a change to how
        the URL conf or DRF exposes the view class fails here instead of quietly checking nothing.
        """
        views = list(iter_api_views())
        self.assertGreater(len(views), 150)
        self.assertGreater(len([cls for _, cls in views if hasattr(cls, "patch")]), 40)

    def test_no_api_view_answers_patch(self):
        """Zentral only does full updates.

        Several serializers read a declared field straight out of validated_data in validate(),
        which a partial update leaves out — a KeyError, and a 500. A view that inherits a patch()
        handler from DRF has to leave the method out of its http_method_names.
        """
        offenders = []
        for path, view_class in iter_api_views():
            if not hasattr(view_class, "patch"):
                continue
            if "patch" in (method.lower() for method in view_class.http_method_names):
                offenders.append(f"{path} {view_class.__module__}.{view_class.__name__}")
        self.assertEqual(sorted(offenders), [])
