from contextlib import contextmanager
import importlib.util
import sys

from django.conf import settings as django_settings
from django.urls import URLResolver
from django.urls.resolvers import RegexPattern

from zentral.conf import settings


_MISSING = object()


@contextmanager
def app_option(app_name, option, value=_MISSING):
    # without a value, the option is left out of the app configuration
    app_conf = settings._collection["apps"]._collection[app_name]._collection
    previous_value = app_conf.pop(option, _MISSING)
    if value is not _MISSING:
        app_conf[option] = value
    try:
        yield
    finally:
        app_conf.pop(option, None)
        if previous_value is not _MISSING:
            app_conf[option] = previous_value


def _new_module_copy(module_name):
    spec = importlib.util.find_spec(module_name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_urlconf(module_name, app_name, option, value=_MISSING):
    # a new copy of the URL module, built with the option. The imported one does not change.
    with app_option(app_name, option, value):
        return _new_module_copy(module_name)


def resolve_in(urlconf, path):
    # not with django.urls.resolve(path, urlconf): its cache would keep each copy until the end of the tests
    return URLResolver(RegexPattern(r"^/"), urlconf).resolve(path)


def load_root_urlconf(app_name, option, value=_MISSING):
    # A new copy of the root URLconf, with new copies of the URL modules of the app, built with the option.
    # The imported modules are put back. Use it with override_settings(ROOT_URLCONF=…), which clears the URL
    # caches on exit.
    package = sys.modules[app_name]
    url_module_names = ("urls", "api_urls", "metrics_urls", "public_urls")
    saved_modules = {name: sys.modules.pop(f"{app_name}.{name}")
                     for name in url_module_names if f"{app_name}.{name}" in sys.modules}
    try:
        with app_option(app_name, option, value):
            return _new_module_copy(django_settings.ROOT_URLCONF)
    finally:
        for name in url_module_names:
            sys.modules.pop(f"{app_name}.{name}", None)
            if name in saved_modules:
                sys.modules[f"{app_name}.{name}"] = saved_modules[name]
                setattr(package, name, saved_modules[name])
            elif hasattr(package, name):
                delattr(package, name)
