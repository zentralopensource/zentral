from django.test import SimpleTestCase
from django.urls import get_resolver
from rest_framework.views import APIView


def iter_api_view_classes(resolver):
    for pattern in resolver.url_patterns:
        if hasattr(pattern, "url_patterns"):
            yield from iter_api_view_classes(pattern)
        else:
            view_class = getattr(pattern.callback, "cls", None)
            if view_class is not None and issubclass(view_class, APIView):
                yield view_class


class APINoPatchTestCase(SimpleTestCase):
    """No API endpoint answers a PATCH.

    The serializers read every declared field, so a partial body is an error and not a partial
    update. The restriction is a class attribute of the audited base classes, and a view that
    does not inherit one of them serves a PATCH without a word.
    """
    maxDiff = None

    def test_no_api_view_answers_a_patch(self):
        checked = 0
        with_patch = set()
        for view_class in iter_api_view_classes(get_resolver()):
            if not hasattr(view_class, "patch"):
                continue
            checked += 1
            if "patch" in view_class.http_method_names:
                with_patch.add(f"{view_class.__module__}.{view_class.__name__}")
        # a walk that resolved no view would assert nothing
        self.assertGreater(checked, 50)
        self.assertEqual(sorted(with_patch), [])
