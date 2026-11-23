from unittest.mock import patch

from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string
from rest_framework import serializers

from accounts.models import Policy, User
from pbac.scoping import visible_rows
from zentral.contrib.inventory.forms import (EnrollmentSecretForm, TagAnyMachineChoiceField,
                                             TagAnyMachineMultipleChoiceField)
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag, Taxonomy
from zentral.contrib.inventory.pbac import TagAnyMachineRequest, refused_pks
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer, TagAnyMachineSerializerMixin
from zentral.contrib.osquery.models import Query


class TagAnyMachineMultipleChoiceFieldTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.tag = Tag.objects.create(name=get_random_string(12))
        cls.refused_tag = Tag.objects.create(name=get_random_string(12))
        role = f'Role::"{cls.group.pk}"'
        Policy.objects.create(
            name=get_random_string(12),
            source=(f'permit (principal in {role}, action == Inventory::Action::"tagAnyMachine", resource);\n'
                    f'forbid (principal in {role}, action == Inventory::Action::"tagAnyMachine", '
                    f'resource == Inventory::Tag::"{cls.refused_tag.pk}");\n')
        )

    def _field(self):
        field = TagAnyMachineMultipleChoiceField(queryset=Tag.objects.all())
        field.set_decision(User.objects.get(pk=self.user.pk), None)
        return field

    def test_integer_values_decided(self):
        self.assertEqual(list(self._field().clean([self.tag.pk])), [self.tag])
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm, self.assertRaises(ValidationError) as ctx:
            self._field().clean([self.tag.pk, self.refused_tag.pk])
        self.assertEqual(ctx.exception.code, "invalid_choice")
        self.assertEqual(ctx.exception.params, {"value": self.refused_tag.pk})
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{self.refused_tag.pk}"> Denied',
                      cm.output[0])

    def test_refused_and_unknown_values(self):
        unknown_tag = Tag.objects.create(name=get_random_string(12))
        unknown_pk = unknown_tag.pk
        unknown_tag.delete()
        # an unknown key and a refused one fail the same way
        with self.assertRaises(ValidationError) as ctx:
            self._field().clean([str(self.refused_tag.pk), str(unknown_pk)])
        self.assertEqual(ctx.exception.code, "invalid_choice")
        self.assertIn(str(ctx.exception.params["value"]), {str(self.refused_tag.pk), str(unknown_pk)})

    def test_not_a_key(self):
        with self.assertNoLogs("zentral.pbac.utils"), self.assertRaises(ValidationError) as ctx:
            self._field().clean([str(self.tag.pk), "yolo"])
        self.assertEqual(ctx.exception.code, "invalid_pk_value")

    def test_not_a_list(self):
        # refused before the decision
        for value in (str(self.refused_tag.pk), self.refused_tag.pk):
            with self.assertNoLogs("zentral.pbac.utils"), self.assertRaises(ValidationError) as ctx:
                self._field().clean(value)
            self.assertEqual(ctx.exception.code, "invalid_list")

    # the decided fields fail closed

    def test_field_without_user(self):
        for field, value in ((TagAnyMachineMultipleChoiceField(queryset=Tag.objects.all()), [self.tag.pk]),
                             (TagAnyMachineChoiceField(queryset=Tag.objects.all()), self.tag.pk)):
            message = f"{field.__class__.__name__} has no user: see DecidedChoicesFormMixin"
            with self.assertRaisesMessage(ImproperlyConfigured, message):
                field.clean(value)
            with self.assertRaisesMessage(ImproperlyConfigured, message):
                list(field.choices)
            with self.assertRaisesMessage(ImproperlyConfigured, message):
                len(field.choices)
            with self.assertRaisesMessage(ImproperlyConfigured, message):
                bool(field.choices)

    def test_form_with_a_none_user(self):
        form = EnrollmentSecretForm({"tags": [self.tag.pk]}, user=None)
        with self.assertRaises(ImproperlyConfigured):
            form.is_valid()

    def test_offered_choices_filtered_once(self):
        with patch("zentral.contrib.inventory.forms.visible_rows", wraps=visible_rows) as wrapped_visible_rows:
            field = self._field()
            self.assertEqual([value.value for value, _ in field.choices], [self.tag.pk])
            self.assertEqual(len(field.choices), 1)
            self.assertTrue(field.choices)
            self.assertEqual([value.value for value, _ in field.widget.choices], [self.tag.pk])
        self.assertEqual(wrapped_visible_rows.call_count, 1)

    def test_no_offered_choice(self):
        field = self._field()
        # a queryset set after the decision is filtered again
        field.queryset = Tag.objects.filter(pk=self.refused_tag.pk)
        self.assertFalse(field.choices)
        self.assertEqual(len(field.choices), 0)
        self.assertEqual(list(field.choices), [])

    # refused_pks locks the rows that the write references, and decides on the rows read again

    def test_refused_pks_locks_the_rows(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        with CaptureQueriesContext(connection) as ctx:
            self.assertEqual(refused_pks(None, User.objects.get(pk=self.user.pk), TagAnyMachineRequest, [tag]), set())
        lock_queries = [query["sql"] for query in ctx.captured_queries if "FOR " in query["sql"]]
        self.assertEqual(len(lock_queries), 2)
        self.assertTrue(lock_queries[0].startswith('SELECT "id" FROM "inventory_tag" '))
        self.assertTrue(lock_queries[1].startswith('SELECT "id" FROM "inventory_taxonomy" '))
        self.assertTrue(all(query.endswith(" FOR SHARE") for query in lock_queries))

    def test_refused_pks_decides_on_the_current_row(self):
        # the rows of a tag that the write read, and that a move or a rename changed since
        refused_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        refused_name = get_random_string(12)
        Policy.objects.create(
            name=get_random_string(12),
            source=(f'forbid (principal in Role::"{self.group.pk}", action == Inventory::Action::"tagAnyMachine", '
                    f'resource in Inventory::Taxonomy::"{refused_taxonomy.pk}");\n'
                    f'forbid (principal in Role::"{self.group.pk}", action == Inventory::Action::"tagAnyMachine", '
                    f'resource) when {{ resource.name == "{refused_name}" }};\n')
        )
        for update in ({"taxonomy": refused_taxonomy}, {"name": refused_name}):
            tag = Tag.objects.create(name=get_random_string(12))
            user = User.objects.get(pk=self.user.pk)
            self.assertEqual(refused_pks(None, user, TagAnyMachineRequest, [tag]), set())
            Tag.objects.filter(pk=tag.pk).update(**update)
            with self.assertLogs("zentral.pbac.utils", level="WARNING"):
                self.assertEqual(refused_pks(None, user, TagAnyMachineRequest, [tag]), {tag.pk})

    def test_refused_pks_deleted_row(self):
        # the row of a tag that the write read, and that a delete removed since
        deleted_tag = Tag.objects.create(name=get_random_string(12))
        Tag.objects.filter(pk=deleted_tag.pk).delete()
        with self.assertNoLogs("zentral.pbac.utils"):
            self.assertEqual(
                refused_pks(None, User.objects.get(pk=self.user.pk), TagAnyMachineRequest, [self.tag, deleted_tag]),
                {deleted_tag.pk}
            )

    def test_refused_pks_no_objects(self):
        with self.assertNumQueries(0):
            self.assertEqual(refused_pks(None, self.user, TagAnyMachineRequest, []), set())


class TagAnyMachineSerializerMixinTestCase(TestCase):
    def test_built_fields(self):
        self.assertIsInstance(EnrollmentSecretSerializer().fields["tags"], serializers.ManyRelatedField)

    def test_tags_not_a_list(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(name=get_random_string(12))
        # refused before the decision: the serializer has no request
        for value, input_type in ((str(tag.pk), "str"), (tag.pk, "int")):
            serializer = EnrollmentSecretSerializer(data={"meta_business_unit": mbu.pk, "tags": value})
            self.assertFalse(serializer.is_valid())
            self.assertEqual(serializer.errors["tags"],
                             [f'Expected a list of items but got type "{input_type}".'])

    def test_declared_many_field_refused(self):
        class DeclaredTagsSerializer(TagAnyMachineSerializerMixin, serializers.ModelSerializer):
            tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True)

            class Meta:
                model = EnrollmentSecret
                fields = ("id", "tags")

        with self.assertRaisesMessage(ImproperlyConfigured, "DeclaredTagsSerializer.tags is not a TagAnyMachineField"):
            DeclaredTagsSerializer().fields

    def test_declared_field_refused(self):
        class DeclaredTagSerializer(TagAnyMachineSerializerMixin, serializers.ModelSerializer):
            tag_any_machine_fields = ("tag",)
            tag = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), allow_null=True)

            class Meta:
                model = Query
                fields = ("id", "tag")

        with self.assertRaisesMessage(ImproperlyConfigured, "DeclaredTagSerializer.tag is not a TagAnyMachineField"):
            DeclaredTagSerializer().fields
