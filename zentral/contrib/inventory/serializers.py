from collections.abc import Mapping
from django.core.exceptions import ImproperlyConfigured
from django.db.models import F
from rest_framework import serializers
from rest_framework.relations import MANY_RELATION_KWARGS
from pbac.utils import check_request
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import FULL_EXPORT_FORMATS, FULL_EXPORT_TABLE_NAMES, get_default_snapshot_retention_days
from .compliance_checks import InventoryJMESPathCheck
from .models import EnrollmentSecret, JMESPathCheck, MetaBusinessUnit, Tag, Taxonomy
from .pbac import CreateTagRequest, TagAnyMachineRequest, refused_pks, renamed_tag_request, renamed_taxonomy_request


# The related fields that a write decides. Their keys can be guessed, so a refused object gets the error of an
# unknown one (rule 13), and the refusal is logged.


class DecidedRelatedFieldMixin:
    def refused_pks(self, objects):
        raise NotImplementedError

    def resolve(self, data):
        # the object, or None for an unknown key. The other errors are raised.
        try:
            return super().to_internal_value(data)
        except serializers.ValidationError as error:
            if error.get_codes() == ["does_not_exist"]:
                return None
            raise

    def to_internal_value(self, data):
        obj = self.resolve(data)
        if obj is None or obj.pk in self.refused_pks([obj]):
            self.fail("does_not_exist", pk_value=data)
        return obj

    @classmethod
    def many_init(cls, *args, **kwargs):
        # the many_init of DRF, with a field that decides all the objects at once
        list_kwargs = {"child_relation": cls(*args, **kwargs)}
        for key in kwargs:
            if key in MANY_RELATION_KWARGS:
                list_kwargs[key] = kwargs[key]
        return DecidedManyRelatedField(**list_kwargs)


class DecidedManyRelatedField(serializers.ManyRelatedField):
    def to_internal_value(self, data):
        if isinstance(data, str) or not hasattr(data, "__iter__"):
            self.fail("not_a_list", input_type=type(data).__name__)
        if not self.allow_empty and len(data) == 0:
            self.fail("empty")
        child = self.child_relation
        resolved = [(item, child.resolve(item)) for item in data]
        refused = child.refused_pks([obj for _, obj in resolved if obj is not None])
        for item, obj in resolved:
            # in the order of the body: an unknown key and a refused one get the same error
            if obj is None or obj.pk in refused:
                child.fail("does_not_exist", pk_value=item)
        return [obj for _, obj in resolved]


# The tags of an object that tags later: tagAnyMachine on each tag that the object has after the save.


class TagAnyMachineField(DecidedRelatedFieldMixin, serializers.PrimaryKeyRelatedField):
    def refused_pks(self, tags):
        http_request = self.context["request"]
        return refused_pks(http_request, http_request.user, TagAnyMachineRequest, tags)


class TagAnyMachineSerializerMixin:
    """For the model serializer of an object that tags later.

    The fields of tag_any_machine_fields are TagAnyMachineField fields. An update requires them: DRF keeps the
    stored value of a field that is not required and not in the body, and the stored tags would then stay on
    the object with no decision.
    """
    tag_any_machine_fields = ("tags",)

    def build_relational_field(self, field_name, relation_info):
        field_class, field_kwargs = super().build_relational_field(field_name, relation_info)
        if field_name in self.tag_any_machine_fields:
            field_class = TagAnyMachineField
        return field_class, field_kwargs

    def get_fields(self):
        fields = super().get_fields()
        # the root has the object of an update, also when this serializer is nested
        update = getattr(self.root, "instance", None) is not None
        for field_name in self.tag_any_machine_fields:
            field = fields[field_name]
            child = field.child_relation if isinstance(field, serializers.ManyRelatedField) else field
            if not isinstance(child, TagAnyMachineField):
                # a declared field skips build_relational_field, and its save would give the tags with no decision
                raise ImproperlyConfigured(f"{self.__class__.__name__}.{field_name} is not a TagAnyMachineField")
            if update:
                field.required = True
        return fields


# Machine mass tagging


class MachineTagsUpdatePrincipalUsers(serializers.Serializer):
    unique_ids = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False
    )
    principal_names = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False
    )

    def validate(self, data):
        if not data.get("unique_ids") and not data.get("principal_names"):
            raise serializers.ValidationError("Unique ids and principal names cannot be both empty.")
        return data


class MachineTagOperation(serializers.Serializer):
    kind = serializers.ChoiceField(choices=(("SET", "Set"), ("ADD", "Add"), ("REMOVE", "Remove")), required=True)
    taxonomy = serializers.CharField(max_length=256, allow_blank=False, allow_null=True, required=False)
    names = serializers.ListField(child=serializers.CharField(),
                                  allow_empty=True, required=True)

    def validate(self, data):
        data = super().validate(data)
        kind = data["kind"]
        taxonomy = data.get("taxonomy")
        names = data.get("names")
        if kind == "SET":
            if not taxonomy:
                raise serializers.ValidationError({"taxonomy": "This field is required for SET operations"})
        elif kind == "REMOVE":
            if taxonomy:
                raise serializers.ValidationError({"taxonomy": "This field may not be set for REMOVE operations"})
            if not names:
                raise serializers.ValidationError({"names": "This list may not be empty for REMOVE operations"})
        elif kind == "ADD":
            if taxonomy:
                raise serializers.ValidationError({"taxonomy": "This field may not be set for ADD operations"})
            if not names:
                raise serializers.ValidationError({"names": "This list may not be empty for ADD operations"})
        return data


class MachineTagsUpdateSerializer(serializers.Serializer):
    principal_users = MachineTagsUpdatePrincipalUsers(required=False)
    serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1),
                                           allow_empty=False, required=False)
    operations = serializers.ListField(child=MachineTagOperation(),
                                       allow_empty=False, required=True)

    def validate(self, data):
        data = super().validate(data)
        if not data.get("principal_users") and not data.get("serial_numbers"):
            raise serializers.ValidationError("principal_users and serial_numbers cannot be both empty.")
        return data


# MetaMachine


class MetaMachineSerializer(serializers.Serializer):
    serial_number = serializers.CharField()
    urlsafe_serial_number = serializers.CharField(source="get_urlsafe_serial_number")
    computer_name = serializers.CharField()
    platform = serializers.CharField()
    type = serializers.CharField()
    tags = serializers.SerializerMethodField()

    def get_tags(self, obj):
        return [{"id": pk, "name": name} for pk, name in obj.tag_pks_and_names]


# Archive or prune machines


class MachineSerialNumbersSerializer(serializers.Serializer):
    serial_numbers = serializers.ListField(
        child=serializers.CharField(min_length=1),
        min_length=1,
        max_length=1000
    )


# Cleanup inventory


class CleanupInventorySerializer(serializers.Serializer):
    days = serializers.IntegerField(min_value=1, max_value=3660, default=get_default_snapshot_retention_days)


class FullExportSerializer(serializers.Serializer):
    export_format = serializers.ChoiceField(choices=FULL_EXPORT_FORMATS, default="JSONL")
    tables = serializers.ListField(
        child=serializers.ChoiceField(
            choices=FULL_EXPORT_TABLE_NAMES,
            error_messages={"invalid_choice": '"{input}" is not a valid table. '
                                              f"Valid tables: {', '.join(FULL_EXPORT_TABLE_NAMES)}."},
        ),
        required=False,
        allow_null=True,
        allow_empty=False,
        error_messages={"empty": f"This list may not be empty. Valid tables: {', '.join(FULL_EXPORT_TABLE_NAMES)}."},
    )

    def validate_tables(self, value):
        if value is None:
            return value
        # canonical order, no duplicates
        return [name for name in FULL_EXPORT_TABLE_NAMES if name in value]


# Standard model serializers


class JMESPathCheckSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source="compliance_check.name")
    description = serializers.CharField(
        source="compliance_check.description",
        allow_blank=True, required=False, default=""
    )
    version = serializers.IntegerField(source="compliance_check.version", read_only=True)
    compliance_check_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = JMESPathCheck
        fields = ("name", "description", "version", "compliance_check_id",
                  "id", "source_name", "platforms", "tags",
                  "jmespath_expression", "created_at", "updated_at")

    def validate_name(self, value):
        qs = ComplianceCheck.objects.filter(model=InventoryJMESPathCheck.get_model(), name=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.compliance_check.pk)
        if qs.count():
            raise serializers.ValidationError(
                f"A {InventoryJMESPathCheck.model_display} with this name already exists."
            )
        return value

    def create(self, validated_data):
        cc_data = validated_data.pop("compliance_check")
        compliance_check = ComplianceCheck.objects.create(
            model=InventoryJMESPathCheck.get_model(),
            name=cc_data.get("name"),
            description=cc_data.get("description") or "",
        )
        tags = validated_data.pop("tags")
        jmespath_check = JMESPathCheck.objects.create(
            compliance_check=compliance_check,
            **validated_data,
        )
        jmespath_check.tags.set(tags)
        return jmespath_check

    def update(self, instance, validated_data):
        # compliance check
        compliance_check = instance.compliance_check
        cc_data = validated_data.pop("compliance_check")
        compliance_check.name = cc_data.get("name")
        compliance_check.description = cc_data.get("description") or ""
        # JMESPath check
        jmespath_check_updated = False
        tags = sorted(validated_data.pop("tags", []), key=lambda t: t.pk)
        for key, value in validated_data.items():
            old_value = getattr(instance, key)
            if value != old_value:
                jmespath_check_updated = True
            setattr(instance, key, value)
        if sorted(instance.tags.all(), key=lambda t: t.pk) != tags:
            jmespath_check_updated = True
        if jmespath_check_updated:
            compliance_check.version = F("version") + 1
        compliance_check.save()
        if jmespath_check_updated:
            # to materialize the updated version
            compliance_check.refresh_from_db()
        instance.save()
        instance.tags.set(tags)
        return instance


class MetaBusinessUnitSerializer(serializers.ModelSerializer):
    api_enrollment_enabled = serializers.BooleanField(required=False)

    class Meta:
        model = MetaBusinessUnit
        fields = ("id", "name", "api_enrollment_enabled", "created_at", "updated_at")
        read_only_fields = ("api_enrollment_enabled",)

    def validate_api_enrollment_enabled(self, value):
        if self.instance and self.instance.api_enrollment_enabled() and not value:
            raise serializers.ValidationError("Cannot disable API enrollment")
        return value

    def create(self, validated_data):
        api_enrollment_enabled = validated_data.pop("api_enrollment_enabled", False)
        mbu = super().create(validated_data)
        if api_enrollment_enabled:
            mbu.create_enrollment_business_unit()
        return mbu

    def update(self, instance, validated_data):
        api_enrollment_enabled = validated_data.pop("api_enrollment_enabled", False)
        mbu = super().update(instance, validated_data)
        if not mbu.api_enrollment_enabled() and api_enrollment_enabled:
            mbu.create_enrollment_business_unit()
        # TODO: switch off api_enrollment_enabled
        return mbu


class CreateTagTaxonomyField(DecidedRelatedFieldMixin, serializers.PrimaryKeyRelatedField):
    """The taxonomy of a tag: createTag on it, except for the taxonomy that the tag has."""

    def refused_pks(self, taxonomies):
        tag = self.parent.instance
        kept_pk = tag.taxonomy_id if tag is not None else None
        http_request = self.context["request"]
        return refused_pks(http_request, http_request.user, CreateTagRequest,
                           [taxonomy for taxonomy in taxonomies if taxonomy.pk != kept_pk])


class TagSerializer(serializers.ModelSerializer):
    taxonomy = CreateTagTaxonomyField(queryset=Taxonomy.objects.all(), allow_null=True, required=False)

    class Meta:
        model = Tag
        fields = ("id", "taxonomy", "meta_business_unit", "name", "slug", "color")

    def to_internal_value(self, data):
        # A tag without taxonomy is created on System::"root". It is decided before the validation: nothing in
        # this refusal can be guessed, so it is a 403.
        if isinstance(data, Mapping):
            no_taxonomy = data.get("taxonomy") in (None, "")
            if self.instance is not None:
                no_taxonomy = no_taxonomy and "taxonomy" in data and self.instance.taxonomy_id is not None
            if no_taxonomy:
                http_request = self.context["request"]
                check_request(http_request, CreateTagRequest(http_request.user, None))
        return super().to_internal_value(data)

    def validate(self, data):
        data = super().validate(data)
        # A rename is decided on the tag with its new name: the name is an attribute that the policies can match.
        # The caller can update the tag, so nothing in this refusal can be guessed: a 403.
        if self.instance is not None and "name" in data and data["name"] != self.instance.name:
            http_request = self.context["request"]
            taxonomy = data["taxonomy"] if "taxonomy" in data else self.instance.taxonomy
            check_request(http_request, renamed_tag_request(http_request.user, self.instance, data["name"], taxonomy))
        return data


class TaxonomySerializer(serializers.ModelSerializer):
    class Meta:
        model = Taxonomy
        fields = ("id", "meta_business_unit", "name", "created_at", "updated_at")

    def validate(self, data):
        data = super().validate(data)
        # A rename is decided like the tag rename: the caller can update the taxonomy, so a 403.
        if self.instance is not None and "name" in data and data["name"] != self.instance.name:
            http_request = self.context["request"]
            check_request(http_request, renamed_taxonomy_request(http_request.user, self.instance, data["name"]))
        return data


class EnrollmentSecretSerializer(TagAnyMachineSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = EnrollmentSecret
        fields = ("id", "secret", "meta_business_unit", "tags", "serial_numbers", "udids", "quota", "request_count")
