from abc import ABC, abstractmethod
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from django.utils.crypto import get_random_string

from accounts.models import Policy
from pbac.engine import engine
from pbac.entities import Entity
from zentral.contrib.inventory.models import Tag, Taxonomy


class TagAnyMachineSaveCase(ABC):
    """The PBAC matrix for one save endpoint of an object that gives tags to machines later.

    The object needs tagAnyMachine on each tag that it has after the save. A refused tag gets the answer of an
    unknown tag. Use it with LoginCase, and with RequestCase for an API endpoint.
    """

    # the legacy permissions of the create and of the update of the object
    tam_permissions = ()
    tam_has_update = True
    # False for an object with one tag
    tam_many = True

    @abstractmethod
    def tam_create(self, tags):
        """Create the object with the tags, as the test principal. Return the response."""

    def tam_force_object(self, tags):
        """An object in the database, with the tags."""

    def tam_update(self, obj, tags, omit_tags=False):
        """Update the object with the tags, as the test principal. Return the response."""

    @abstractmethod
    def tam_saved_tags(self, response=None, obj=None):
        """The tags of the object that the response created, or of the stored object, as a set."""

    @abstractmethod
    def tam_assert_saved(self, response):
        pass

    @abstractmethod
    def tam_assert_refused(self, response, tag):
        """The answer of an unknown tag."""

    @abstractmethod
    def tam_assert_not_a_primary_key(self, response):
        pass

    def tam_unknown_tag(self):
        tag = Tag.objects.create(name=get_random_string(12))
        pk = tag.pk
        tag.delete()
        tag.pk = pk
        return tag

    # policies

    def tam_set_policies(self, *statements, tag_action=True):
        role = Entity("Role", str(self._get_group().pk))
        self.set_permissions(*self.tam_permissions)
        source = ""
        if tag_action:
            source = f'permit (principal in {role}, action == Inventory::Action::"tagAnyMachine", resource);\n'
        source += "".join(
            f'{effect} (principal in {role}, action == Inventory::Action::"{action_id}", {scope}){when};\n'
            for effect, action_id, scope, when in statements
        )
        if source:
            Policy.objects.update_or_create(name="Tests tag actions", defaults={"source": source})
        else:
            Policy.objects.filter(name="Tests tag actions").delete()

    def tam_force_tag(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        return Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))

    def tam_tags(self, *tags):
        return list(tags) if self.tam_many else list(tags[:1])

    def tam_assert_created_with(self, response, tags):
        self.tam_assert_saved(response)
        self.assertEqual(self.tam_saved_tags(response=response), set(tags))

    # create

    def test_tam_create_without_the_action(self):
        tag = self.tam_force_tag()
        self.tam_set_policies(tag_action=False)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self.tam_create([tag])
        self.tam_assert_refused(response, tag)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{tag.pk}"', cm.output[0])

    def test_tam_create_unknown_tag(self):
        self.tam_set_policies()
        tag = self.tam_unknown_tag()
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.tam_create([tag])
        self.tam_assert_refused(response, tag)

    def test_tam_create_not_a_primary_key(self):
        self.tam_set_policies()
        for value in ("yolo", True, [1]):
            with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
                response = self.tam_create([SimpleNamespace(pk=value)])
            self.tam_assert_not_a_primary_key(response)

    def test_tam_create_without_tag_without_the_action(self):
        self.tam_set_policies(tag_action=False)
        self.tam_assert_created_with(self.tam_create([]), [])

    def test_tam_create_with_the_action(self):
        tags = self.tam_tags(self.tam_force_tag(), self.tam_force_tag())
        self.tam_set_policies()
        self.tam_assert_created_with(self.tam_create(tags), tags)

    def test_tam_create_forbid_another_action(self):
        tag = self.tam_force_tag()
        self.tam_set_policies(("forbid", "createTag", "resource", ""),
                              ("forbid", "createMachineTag", "resource", ""))
        self.tam_assert_created_with(self.tam_create([tag]), [tag])

    def test_tam_create_forbid_the_tag(self):
        tag = self.tam_force_tag()
        self.tam_set_policies(("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{tag.pk}"', ""))
        self.tam_assert_refused(self.tam_create([tag]), tag)

    def test_tam_create_forbid_the_taxonomy(self):
        tag = self.tam_force_tag()
        self.tam_set_policies(
            ("forbid", "tagAnyMachine", f'resource in Inventory::Taxonomy::"{tag.taxonomy.pk}"', "")
        )
        self.tam_assert_refused(self.tam_create([tag]), tag)

    def test_tam_create_forbid_the_name(self):
        tag = self.tam_force_tag()
        self.tam_set_policies(
            ("forbid", "tagAnyMachine", "resource", f' when {{ resource.name == "{tag.name}" }}')
        )
        self.tam_assert_refused(self.tam_create([tag]), tag)

    def test_tam_create_forbid_with_a_decision_for_each_tag(self):
        # `like` is not in the SQL subset, so each tag gets its own decision: the same answers
        tag = self.tam_force_tag()
        other_tag = self.tam_force_tag()
        self.tam_set_policies(
            ("forbid", "tagAnyMachine", "resource", f' when {{ resource.name like "{tag.name}*" }}')
        )
        self.tam_assert_refused(self.tam_create([tag]), tag)
        self.tam_assert_created_with(self.tam_create([other_tag]), [other_tag])

    def test_tam_create_one_refused_tag(self):
        if not self.tam_many:
            self.skipTest("one tag")
        tag = self.tam_force_tag()
        refused_tag = self.tam_force_tag()
        self.tam_set_policies(("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{refused_tag.pk}"', ""))
        self.tam_assert_refused(self.tam_create([tag, refused_tag]), refused_tag)

    def test_tam_create_one_decision(self):
        tags = self.tam_tags(self.tam_force_tag(), self.tam_force_tag(), self.tam_force_tag())
        self.tam_set_policies(("forbid", "tagAnyMachine", 'resource == Inventory::Tag::"0"', ""))
        with self.tam_count_decisions() as decisions:
            response = self.tam_create(tags)
        self.tam_assert_saved(response)
        # one batch, with each posted tag
        self.assertEqual(len(decisions), 1)
        self.assertEqual(sorted(request.resource.id for request in decisions[0]), sorted(str(tag.pk) for tag in tags))

    @contextmanager
    def tam_count_decisions(self):
        decisions = []
        original = engine.authorize_requests

        def authorize_requests(requests):
            requests = list(requests)
            tag_requests = [request for request in requests if request.action.id == "tagAnyMachine"]
            if tag_requests:
                decisions.append(tag_requests)
            return original(requests)

        with patch.object(engine, "authorize_requests", side_effect=authorize_requests):
            yield decisions

    # update

    def test_tam_update_without_the_action(self):
        if not self.tam_has_update:
            self.skipTest("no update")
        tag = self.tam_force_tag()
        obj = self.tam_force_object([tag])
        self.tam_set_policies(tag_action=False)
        self.tam_assert_refused(self.tam_update(obj, [tag]), tag)
        self.assertEqual(self.tam_saved_tags(obj=obj), {tag})

    def test_tam_update_with_the_action(self):
        if not self.tam_has_update:
            self.skipTest("no update")
        tag = self.tam_force_tag()
        new_tag = self.tam_force_tag()
        obj = self.tam_force_object([tag])
        self.tam_set_policies()
        self.tam_assert_saved(self.tam_update(obj, [new_tag]))
        self.assertEqual(self.tam_saved_tags(obj=obj), {new_tag})

    def test_tam_update_forbid_the_new_tag(self):
        if not self.tam_has_update:
            self.skipTest("no update")
        tag = self.tam_force_tag()
        new_tag = self.tam_force_tag()
        obj = self.tam_force_object([tag])
        self.tam_set_policies(("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{new_tag.pk}"', ""))
        self.tam_assert_refused(self.tam_update(obj, [new_tag]), new_tag)
        self.assertEqual(self.tam_saved_tags(obj=obj), {tag})

    def test_tam_update_remove_the_tags_without_the_action(self):
        if not self.tam_has_update:
            self.skipTest("no update")
        obj = self.tam_force_object([self.tam_force_tag()])
        self.tam_set_policies(tag_action=False)
        self.tam_assert_saved(self.tam_update(obj, []))
        self.assertEqual(self.tam_saved_tags(obj=obj), set())


class TagAnyMachineAPISaveCase(TagAnyMachineSaveCase):
    """For an API endpoint: a refused tag gets the 400 of an unknown primary key."""
    # the path of the tags in the errors of the response
    tam_error_path = ("tags",)

    def tam_assert_saved(self, response):
        self.assertIn(response.status_code, (200, 201), response.content)

    def tam_assert_refused(self, response, tag):
        self.assertEqual(response.status_code, 400, response.content)
        errors = response.json()
        for key in self.tam_error_path:
            errors = errors[key]
        self.assertEqual(errors, [f'Invalid pk "{tag.pk}" - object does not exist.'])

    def tam_assert_not_a_primary_key(self, response):
        self.assertEqual(response.status_code, 400, response.content)
        errors = response.json()
        for key in self.tam_error_path:
            errors = errors[key]
        self.assertEqual(len(errors), 1)

    def test_tam_update_without_the_tags_in_the_body(self):
        # the stored tags would stay with no decision: with or without the action, the PUT must carry the tags
        tag = self.tam_force_tag()
        for stored_tags, tag_action in (([tag], False), ([tag], True), ([], True)):
            obj = self.tam_force_object(stored_tags)
            self.tam_set_policies(tag_action=tag_action)
            response = self.tam_update(obj, [], omit_tags=True)
            self.assertEqual(response.status_code, 400, response.content)
            errors = response.json()
            for key in self.tam_error_path:
                errors = errors[key]
            self.assertEqual(errors, ["This field is required."])
            self.assertEqual(self.tam_saved_tags(obj=obj), set(stored_tags))


class TagAnyMachineFormSaveCase(TagAnyMachineSaveCase):
    """For a console form: a refused tag is not a valid choice, as an unknown tag."""
    # the name of the form in the context of the response, and the name of its field
    tam_form_name = "form"
    tam_field_name = "tags"

    def tam_assert_saved(self, response):
        # the redirect of a valid form, not followed
        self.assertEqual(response.status_code, 302, response.context and response.context[self.tam_form_name].errors)

    def tam_assert_refused(self, response, tag):
        self.assertEqual(response.status_code, 200)
        if self.tam_many:
            error = f"Select a valid choice. {tag.pk} is not one of the available choices."
        else:
            error = "Select a valid choice. That choice is not one of the available choices."
        self.assertEqual(response.context[self.tam_form_name].errors, {self.tam_field_name: [error]})

    def tam_assert_not_a_primary_key(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context[self.tam_form_name].errors), [self.tam_field_name])

    def test_tam_form_choices(self):
        if not self.tam_has_update:
            self.skipTest("no update")
        tag = self.tam_force_tag()
        refused_tag = self.tam_force_tag()
        obj = self.tam_force_object([refused_tag])
        self.tam_set_policies(("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{refused_tag.pk}"', ""))
        response = self.tam_get_update_form(obj)
        field = response.context[self.tam_form_name].fields[self.tam_field_name]
        choices = {value.instance for value, _ in field.choices if value}
        self.assertIn(tag, choices)
        self.assertNotIn(refused_tag, choices)
        # the choices are a filter: the validation keeps every tag, and the posted one is decided
        self.assertIn(refused_tag, field.queryset)

    def tam_get_update_form(self, obj):
        """The response of the GET of the update form."""
