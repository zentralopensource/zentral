import inspect
import re
import sys
import types
import unittest
import uuid
from unittest.mock import patch
from django.apps import apps
from django.test import RequestFactory, SimpleTestCase, TestCase
from zentral.core.events.base import AuditEvent, EventMetadata, linked_objects_key
from zentral.core.stores.views.events import EventsViewMixin
from tests.linked_objects_keys import (FailOnUnknownLinkedObjectsKeysMixin, LinkedObjectsKeysCheck, MENTION_KEYS,
                                       class_name, pop_unknown_keys, record_unknown_keys, unknown_keys_error)
from tests.runner import ZentralTestSuite


class FakeMeta:
    def __init__(self, app_label, verbose_name):
        self.app_label = app_label
        self.verbose_name = verbose_name
        self.label_lower = f"{app_label}.{verbose_name.replace(' ', '')}"


class FakeInstance:
    """The part of a model that AuditEvent.build() reads."""

    def __init__(self, pk, app_label="osquery", verbose_name="file category"):
        self.pk = pk
        self._meta = FakeMeta(app_label, verbose_name)


class ParentsOnlyInstance(FakeInstance):
    def linked_objects_keys_for_event(self):
        return {"osquery_configuration": ((42,),)}


class OwnKeyInstance(FakeInstance):
    """Links itself by something other than its primary key, like the MDM device commands."""

    def linked_objects_keys_for_event(self):
        return {"osquery_file_category": ((f"uuid-{self.pk}",),)}


class RenamedKeyInstance(FakeInstance):
    linked_objects_key = "accounts_oidc_api_token_issuer"


class LinkedObjectsKeyTestCase(TestCase):
    def test_key_from_the_verbose_name(self):
        self.assertEqual(linked_objects_key(FakeInstance(1)), "osquery_file_category")

    def test_inventory_keys_have_no_app_label(self):
        self.assertEqual(linked_objects_key(FakeInstance(1, app_label="inventory", verbose_name="tag")), "tag")

    def test_declared_key_wins(self):
        self.assertEqual(linked_objects_key(RenamedKeyInstance(1)), "accounts_oidc_api_token_issuer")


class AuditEventObjectsTestCase(TestCase):
    def _objects(self, instance):
        event = AuditEvent.build(instance, AuditEvent.Action.DELETED, prev_value={"pk": instance.pk})
        return event.metadata.objects

    def test_object_without_linked_objects_is_linked_to_itself(self):
        self.assertEqual(self._objects(FakeInstance(1)), {"osquery_file_category": [(1,)]})

    def test_parents_do_not_replace_the_link_to_the_object(self):
        self.assertEqual(
            self._objects(ParentsOnlyInstance(2)),
            {"osquery_file_category": [(2,)],
             "osquery_configuration": [(42,)]}
        )

    def test_a_declared_own_key_keeps_control_of_its_arguments(self):
        self.assertEqual(self._objects(OwnKeyInstance(3)), {"osquery_file_category": [("uuid-3",)]})

    def test_a_renamed_key_is_used_for_the_object(self):
        self.assertEqual(self._objects(RenamedKeyInstance(4)), {"accounts_oidc_api_token_issuer": [(4,)]})


# a model writes its own key with its own pk in one of these two spellings
OWN_PK = r"(\[\(self\.pk,\)\]|\(\(self\.pk,\),\))"


class RedundantSelfKeysTestCase(SimpleTestCase):
    """AuditEvent.build() links the object of the event on its own.

    A model that writes its own key with its own pk in linked_objects_keys_for_event() does the
    same work a second time. A model that writes its own key with something else keeps control of
    it — the MDM commands link themselves by uuid — so only the pk spelling is a defect.
    """

    def iter_hooks(self):
        for model in apps.get_models():
            hook = getattr(model, "linked_objects_keys_for_event", None)
            if hook is not None:
                yield model, hook

    def test_the_traversal_finds_the_hooks(self):
        """A guard that stops traversing passes for the wrong reason."""
        self.assertGreater(len(list(self.iter_hooks())), 10)

    def test_no_model_writes_its_own_key_with_its_own_pk(self):
        offenders = []
        for model, hook in self.iter_hooks():
            own_key = linked_objects_key(model)
            if re.search(rf'"{re.escape(own_key)}":\s*{OWN_PK}', inspect.getsource(hook)):
                offenders.append(f"{model._meta.label} {own_key}")
        self.assertEqual(sorted(offenders), [])


class RecordingResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.successes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)


class LinkedObjectsKeysCheckTestCase(SimpleTestCase):
    """The check of the test runner records the keys that are neither a model key nor a mention key."""

    def assertNoUnknownKeys(self):
        self.assertEqual(pop_unknown_keys(), [])

    def test_mention_keys_are_not_model_keys(self):
        model_keys = set(linked_objects_key(model) for model in apps.get_models())
        self.assertEqual(MENTION_KEYS & model_keys, set())

    def test_a_model_key_is_not_recorded(self):
        EventMetadata().add_objects({"santa_configuration": [(1,)]})
        self.assertNoUnknownKeys()

    def test_a_mention_key_is_not_recorded(self):
        EventMetadata().add_objects({"apple_team_id": [("MZ6DLR4PNC",)]})
        self.assertNoUnknownKeys()

    def test_an_unknown_key_is_recorded(self):
        EventMetadata().add_objects({"realms_realm_user": [(1,)]})
        unknown_keys = pop_unknown_keys()
        self.assertEqual(len(unknown_keys), 1)
        self.assertTrue(unknown_keys[0].startswith("'realms_realm_user' written, from "))
        self.assertIn("test_audit_event_objects.py:", unknown_keys[0])

    def test_an_unknown_key_of_an_event_names_its_event_type(self):
        event = AuditEvent(EventMetadata(), {})
        event.metadata.add_objects({"realms_realm_user": [(1,)]})
        unknown_keys = pop_unknown_keys()
        self.assertEqual(len(unknown_keys), 1)
        self.assertTrue(unknown_keys[0].startswith("'realms_realm_user' written by a zentral_audit event, from "))

    def test_an_unknown_key_of_a_collected_event_is_recorded(self):
        metadata = EventMetadata()
        AuditEvent(metadata, {})
        with self.assertRaises(ReferenceError):
            metadata.event.event_type
        metadata.add_objects({"realms_realm_user": [(1,)]})
        unknown_keys = pop_unknown_keys()
        self.assertEqual(len(unknown_keys), 1)
        self.assertTrue(unknown_keys[0].startswith("'realms_realm_user' written, from "))

    def test_unknown_keys_of_mixed_types_are_recorded(self):
        record_unknown_keys((None, "realms_realm_user"), "written")
        self.assertEqual([unknown_key.split(" ")[0] for unknown_key in pop_unknown_keys()],
                         ["'realms_realm_user'", "None"])

    def test_a_deserialized_event_keeps_its_keys(self):
        event = AuditEvent.deserialize({"_zentral": {"id": str(uuid.uuid4()),
                                                     "index": 0,
                                                     "objects": {"realms_realm_user": ["1"]}}})
        self.assertEqual(event.metadata.objects, {"realms_realm_user": [["1"]]})
        self.assertNoUnknownKeys()

    def fetch_kwargs(self, fetch_kwargs_extra):
        class TestEventsView(EventsViewMixin):
            def get_fetch_kwargs_extra(self):
                return fetch_kwargs_extra.copy()

        view = TestEventsView()
        view.request = RequestFactory().get("/")
        return view.clean_fetch_kwargs()

    def test_a_fetched_model_key_is_not_recorded(self):
        self.assertEqual(self.fetch_kwargs({"key": "santa_configuration", "val": "1"})["key"], "santa_configuration")
        self.assertNoUnknownKeys()

    def test_a_fetch_without_key_is_not_recorded(self):
        self.assertEqual(self.fetch_kwargs({"serial_number": "0123456789"})["serial_number"], "0123456789")
        self.assertNoUnknownKeys()

    def test_an_unknown_fetched_key_is_recorded(self):
        self.fetch_kwargs({"key": "realms_realm_user", "val": "1"})
        unknown_keys = pop_unknown_keys()
        self.assertEqual(len(unknown_keys), 1)
        self.assertTrue(unknown_keys[0].startswith("'realms_realm_user' asked for by TestEventsView, from "))

    def test_an_unknown_constructor_key_is_recorded(self):
        EventMetadata(objects={"realms_realm_user": [(1,)]})
        unknown_keys = pop_unknown_keys()
        self.assertEqual(len(unknown_keys), 1)
        self.assertTrue(unknown_keys[0].startswith("'realms_realm_user' given to EventMetadata, from "))
        self.assertIn("test_audit_event_objects.py:", unknown_keys[0])

    def test_a_constructor_model_key_is_not_recorded(self):
        EventMetadata(objects={"santa_configuration": [(1,)]})
        self.assertNoUnknownKeys()

    def test_no_unknown_keys_no_error(self):
        self.assertIsNone(unknown_keys_error("in a test"))

    def test_the_error_has_a_traceback(self):
        record_unknown_keys(("realms_realm_user",), "written")
        exc_type, exc_value, tb = unknown_keys_error("in a test")
        self.assertIs(exc_type, AssertionError)
        self.assertTrue(str(exc_value).startswith(
            "Unknown linked objects keys in a test:\n'realms_realm_user' written"
        ))
        self.assertIsNotNone(tb)

    def run_test(self, *unknown_keys, outcome="success"):
        result = type("TestResult", (FailOnUnknownLinkedObjectsKeysMixin, RecordingResult), {})()
        result.startTest(self)
        record_unknown_keys(unknown_keys, "written")
        if outcome == "success":
            result.addSuccess(self)
        else:
            result.addError(self, (ValueError, ValueError("yolo"), None))
        result.stopTest(self)
        return result

    def test_an_unknown_key_fails_a_passing_test_once(self):
        result = self.run_test("realms_realm_user")
        self.assertEqual(result.successes, [])
        self.assertEqual(len(result.failures), 1)
        failed_test, error = result.failures[0]
        self.assertIs(failed_test, self)
        self.assertIn(f"Unknown linked objects keys in {self.id()}:\n'realms_realm_user' written, from ", error)

    def test_an_unknown_key_of_a_failing_test_is_reported(self):
        result = self.run_test("realms_realm_user", outcome="error")
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(len(result.failures), 1)
        self.assertIn("'realms_realm_user' written", result.failures[0][1])

    def test_known_keys_do_not_fail_the_test(self):
        result = self.run_test("santa_configuration", "apple_team_id")
        self.assertEqual(result.successes, [self])
        self.assertEqual(result.failures, [])

    def test_a_key_written_between_two_tests_is_not_charged_to_the_next_test(self):
        result = type("TestResult", (FailOnUnknownLinkedObjectsKeysMixin, RecordingResult), {})()
        record_unknown_keys(("realms_realm_user",), "written")
        result.startTest(self)
        result.addSuccess(self)
        result.stopTest(self)
        self.assertEqual(result.successes, [self])
        self.assertEqual(result.failures, [])
        self.assertEqual(len(result.errors), 1)
        holder, error = result.errors[0]
        self.assertEqual(str(holder), f"linked objects keys before {self.id()}")
        self.assertIn("'realms_realm_user' written", error)

    def test_keys_written_before_the_tests_are_reported_once(self):
        result = type("TestResult", (FailOnUnknownLinkedObjectsKeysMixin, RecordingResult), {})()
        record_unknown_keys(("realms_realm_user",), "written")
        result.startTestRun()
        self.assertEqual([str(holder) for holder, _ in result.errors], ["linked objects keys before the tests"])
        self.assertIn("'realms_realm_user' written", result.errors[0][1])
        self.assertNoUnknownKeys()

    def test_keys_written_by_the_fixtures_are_not_charged_to_a_test(self):
        module = types.ModuleType("tests.core_events.linked_objects_keys_fixtures")
        module.setUpModule = lambda: record_unknown_keys(("module_setup_key",), "written")
        module.tearDownModule = lambda: record_unknown_keys(("module_teardown_key",), "written")
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__)

        class SetUpClassKeyTestCase(unittest.TestCase):
            __module__ = module.__name__

            @classmethod
            def setUpClass(cls):
                record_unknown_keys(("class_setup_key",), "written")

            def test_nothing(self):
                pass

        class TearDownClassKeyTestCase(unittest.TestCase):
            __module__ = module.__name__

            @classmethod
            def tearDownClass(cls):
                record_unknown_keys(("class_teardown_key",), "written")

            def test_nothing(self):
                pass

        result = type("TestResult", (FailOnUnknownLinkedObjectsKeysMixin, RecordingResult), {})()
        suite = ZentralTestSuite([SetUpClassKeyTestCase("test_nothing"), TearDownClassKeyTestCase("test_nothing")])
        # the suite in this test must not clear the caches or run the module cleanups of the other tests
        with patch("tests.runner.clear_caches") as clear_caches, \
             patch("unittest.case.doModuleCleanups") as do_module_cleanups:
            suite.run(result)
        self.assertEqual(clear_caches.call_count, 2)
        do_module_cleanups.assert_called_once_with()
        self.assertEqual(len(result.successes), 2)
        self.assertEqual(result.failures, [])
        self.assertEqual(
            [str(holder) for holder, _ in result.errors],
            [f"linked objects keys in setUpModule of {module.__name__}",
             f"linked objects keys in setUpClass of {class_name(SetUpClassKeyTestCase)}",
             f"linked objects keys after the tests of {class_name(TearDownClassKeyTestCase)}",
             f"linked objects keys in tearDownModule of {module.__name__}"]
        )
        keys = ("module_setup_key", "class_setup_key", "class_teardown_key", "module_teardown_key")
        for (_, error), key in zip(result.errors, keys, strict=True):
            self.assertIn(f"'{key}' written", error)

    def test_disable_restores_the_methods(self):
        init = EventMetadata.__init__
        add_objects = EventMetadata.add_objects
        clean_fetch_kwargs = EventsViewMixin.clean_fetch_kwargs
        check = LinkedObjectsKeysCheck()
        check.enable()
        try:
            self.assertIsNot(EventMetadata.__init__, init)
            self.assertIsNot(EventMetadata.add_objects, add_objects)
            self.assertIsNot(EventsViewMixin.clean_fetch_kwargs, clean_fetch_kwargs)
            EventMetadata().add_objects({"realms_realm_user": [(1,)]})
        finally:
            check.disable()
        self.assertIs(EventMetadata.__init__, init)
        self.assertIs(EventMetadata.add_objects, add_objects)
        self.assertIs(EventsViewMixin.clean_fetch_kwargs, clean_fetch_kwargs)
        self.assertNoUnknownKeys()
