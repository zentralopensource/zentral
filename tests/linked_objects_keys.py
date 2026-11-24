import os
import sys
import traceback
from unittest.suite import _ErrorHolder


# the keys that have no model to align to: an event mentions something, it does not link a Zentral object
MENTION_KEYS = {
    # a team identifier of an Apple developer, with no model
    "apple_team_id",
    # a munki report knows the name and the version of a package, not a pk
    "munki_pkginfo",
    # a munki report knows the name of a package, not a pk
    "munki_pkginfo_name",
}


_allowed_keys = None
_unknown_keys = []


def allowed_keys():
    global _allowed_keys
    if _allowed_keys is None:
        from django.apps import apps
        from zentral.core.events.base import linked_objects_key
        _allowed_keys = frozenset(linked_objects_key(model) for model in apps.get_models()) | MENTION_KEYS
    return _allowed_keys


def _caller():
    # the first frame outside of the event machinery and of this module
    skipped = (os.path.join("zentral", "core", "events", "base.py"),
               os.path.join("zentral", "core", "stores", "views", "events.py"),
               os.path.join("tests", "linked_objects_keys.py"))
    for frame in reversed(traceback.extract_stack()):
        if not frame.filename.endswith(skipped):
            return f"{frame.filename}:{frame.lineno}"


def record_unknown_keys(keys, source):
    # repr: a wrong key can be of any type, and the check must not raise
    for key in sorted(set(keys) - allowed_keys(), key=repr):
        _unknown_keys.append(f"{key!r} {source}, from {_caller()}")


def pop_unknown_keys():
    unknown_keys = list(_unknown_keys)
    _unknown_keys.clear()
    return unknown_keys


def _event_type(metadata):
    try:
        return metadata.event.event_type
    except (AttributeError, ReferenceError):
        # the metadata of an audit event gets its keys before its event, and the event is a weak reference
        return None


class LinkedObjectsKeysCheck:
    """Record the linked objects keys that are neither the key of a model nor a mention key.

    The written keys are checked where an event gets them, so a key built by a helper or kept in a variable
    is checked too. The events of a store keep their keys: a deserialized event is not checked.
    """

    def __init__(self):
        self._patches = []

    def _patch(self, cls, name, wrapper_factory):
        original = getattr(cls, name)
        setattr(cls, name, wrapper_factory(original))
        self._patches.append((cls, name, original))

    def enable(self):
        from zentral.core.events.base import EventMetadata
        from zentral.core.stores.views.events import EventsViewMixin

        def add_objects_factory(original):
            def add_objects(metadata, extra_objects):
                event_type = _event_type(metadata)
                source = f"written by a {event_type} event" if event_type else "written"
                record_unknown_keys(extra_objects, source)
                return original(metadata, extra_objects)
            return add_objects

        def clean_fetch_kwargs_factory(original):
            def clean_fetch_kwargs(view):
                kwargs = original(view)
                if "key" in kwargs:
                    record_unknown_keys((kwargs["key"],), f"asked for by {view.__class__.__name__}")
                return kwargs
            return clean_fetch_kwargs

        def init_factory(original):
            def __init__(metadata, **kwargs):
                if not kwargs.get("_deserialized") and kwargs.get("objects"):
                    record_unknown_keys(kwargs["objects"], "given to EventMetadata")
                original(metadata, **kwargs)
            return __init__

        self._patch(EventMetadata, "__init__", init_factory)
        self._patch(EventMetadata, "add_objects", add_objects_factory)
        self._patch(EventsViewMixin, "clean_fetch_kwargs", clean_fetch_kwargs_factory)

    def disable(self):
        while self._patches:
            cls, name, original = self._patches.pop()
            setattr(cls, name, original)
        pop_unknown_keys()


def unknown_keys_error(where):
    unknown_keys = pop_unknown_keys()
    if not unknown_keys:
        return None
    # a real traceback: --pdb opens a post-mortem session on it, and tblib pickles it for a parallel run
    try:
        raise AssertionError(f"Unknown linked objects keys {where}:\n" + "\n".join(unknown_keys))
    except AssertionError:
        return sys.exc_info()


def report_unknown_keys_outside_tests(result, where):
    err = unknown_keys_error(where)
    if err:
        # in a parallel run, Django gives the error to the last test that started, so the message says where
        result.addError(_ErrorHolder(f"linked objects keys {where}"), err)


def class_name(cls):
    return f"{cls.__module__}.{cls.__qualname__}"


class FailOnUnknownLinkedObjectsKeysMixin:
    def startTestRun(self):
        super().startTestRun()
        # the keys written while the test databases were set up, before a parallel run forks its workers
        report_unknown_keys_outside_tests(self, "before the tests")

    def startTest(self, test):
        # a Django test case tears down its fixtures after stopTest
        report_unknown_keys_outside_tests(self, f"before {test.id()}")
        super().startTest(test)

    def addSuccess(self, test):
        err = unknown_keys_error(f"in {test.id()}")
        if err:
            self.addFailure(test, err)
        else:
            super().addSuccess(test)

    def stopTest(self, test):
        # the test failed for another reason, or it was skipped
        err = unknown_keys_error(f"in {test.id()}")
        if err:
            self.addFailure(test, err)
        super().stopTest(test)
