import inspect
import re
from django.apps import apps
from django.test import SimpleTestCase, TestCase
from zentral.core.events.base import AuditEvent, linked_objects_key


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
