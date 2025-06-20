import logging
from django.urls import reverse_lazy
from django.utils.functional import cached_property
from rest_framework import serializers
from zentral.contrib.inventory.conf import (PLATFORM_CHOICES, PLATFORM_CHOICES_DICT,
                                            TYPE_CHOICES, TYPE_CHOICES_DICT)
from zentral.core.events import event_types
from zentral.core.incidents.models import Severity
from .action_backends import get_action_backend
from .incidents import ProbeIncident


logger = logging.getLogger('zentral.core.probes.probe')


class InventoryFilter:
    def __init__(self, data):
        for attr in ("meta_business_unit_ids", "tag_ids", "platforms", "types"):
            setattr(self, attr, set(data.get(attr, [])))

    def test_machine(self, meta_machine):
        m_platform, m_type, m_mbu_id_set, m_tag_id_set = meta_machine.cached_probe_filtering_values
        if self.meta_business_unit_ids and not self.meta_business_unit_ids & m_mbu_id_set:
            return False
        if self.tag_ids and not self.tag_ids & m_tag_id_set:
            return False
        if self.platforms and m_platform not in self.platforms:
            return False
        if self.types and m_type not in self.types:
            return False
        return True

    @cached_property
    def meta_business_units(self):
        # TODO: import loop
        from zentral.contrib.inventory.models import MetaBusinessUnit
        return list(MetaBusinessUnit.objects.filter(pk__in=self.meta_business_unit_ids))

    @cached_property
    def tags(self):
        # TODO: import loop
        from zentral.contrib.inventory.models import Tag
        return list(Tag.objects.filter(pk__in=self.tag_ids))

    def get_platforms_display(self):
        return ", ".join(sorted((PLATFORM_CHOICES_DICT.get(p, p)
                                 for p in self.platforms),
                                key=lambda s: s.lower()))

    def get_types_display(self):
        return ", ".join(sorted((TYPE_CHOICES_DICT.get(t, t)
                                 for t in self.types),
                                key=lambda s: s.lower()))


class InventoryFilterSerializer(serializers.Serializer):
    meta_business_unit_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False
    )
    tag_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=False
    )
    platforms = serializers.MultipleChoiceField(
        choices=PLATFORM_CHOICES,
        required=False
    )
    types = serializers.MultipleChoiceField(
        choices=TYPE_CHOICES,
        required=False
    )

    def validate(self, data):
        # MultipleChoiceField return sets that are not JSON serializable
        for key in ("platforms", "types"):
            if isinstance(data.get(key), set):
                data[key] = list(data.pop(key))
        for key, val in data.items():
            if val:
                return data
        raise serializers.ValidationError("No business units, tags, platforms or types")


class MetadataFilter:
    def __init__(self, data):
        event_types = data.get("event_types")
        if event_types is None:
            event_types = []
        self.event_types = set(event_types)
        event_tags = data.get("event_tags")
        if event_tags is None:
            event_tags = []
        self.event_tags = set(event_tags)
        event_routing_keys = data.get("event_routing_keys")
        if event_routing_keys is None:
            event_routing_keys = []
        self.event_routing_keys = set(event_routing_keys)

    def test_event_metadata(self, metadata):
        if self.event_types and metadata.event_type not in self.event_types:
            return False
        if self.event_tags and not metadata.all_tags & self.event_tags:
            return False
        if self.event_routing_keys and metadata.routing_key not in self.event_routing_keys:
            return False
        return True

    def get_event_type_classes(self):
        etl = []
        for et in self.event_types:
            try:
                et = event_types[et]
            except KeyError:
                logger.warning("Unknown event type %s in metadata filter", et)
            else:
                etl.append(et)
        etl.sort(key=lambda et: et.get_event_type_display())
        return etl

    def get_event_types_display(self):
        return ", ".join(et.get_event_type_display()
                         for et in self.get_event_type_classes())

    def get_event_tags_display(self):
        return ", ".join(sorted(t.replace("_", " ")
                                for t in self.event_tags))

    def get_event_routing_keys_display(self):
        return ", ".join(sorted(self.event_routing_keys))


class MetadataFilterSerializer(serializers.Serializer):
    event_types = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    event_tags = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    event_routing_keys = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )

    def validate(self, data):
        for key, val in data.items():
            if val:
                return data
        raise serializers.ValidationError("No event types or tags")


def get_flattened_payload_values(payload, attrs):
    if isinstance(payload, list):
        for nested_payload in payload:
            yield from get_flattened_payload_values(nested_payload, list(attrs))
    elif isinstance(payload, dict):
        attr = attrs.pop(0)
        val = payload.get(attr)
        if val is None:
            return
        if not attrs:
            if isinstance(val, (set, list)):
                yield from (str(v) for v in val)
            else:
                yield str(val)
        else:
            yield from get_flattened_payload_values(val, attrs)
    else:
        logger.warning("Wrong payload filter attribute %s", attrs)


class PayloadFilter:
    IN = "IN"
    NOT_IN = "NOT_IN"
    operator_choices = (
        (IN, "="),
        (NOT_IN, "!="),
    )

    def __init__(self, data):
        self.items = []
        for payload_filter_item_d in data:
            attribute = payload_filter_item_d["attribute"]
            operator = payload_filter_item_d["operator"]
            if operator not in (self.IN, self.NOT_IN):
                raise ValueError("Unknown operator '{}'".format(operator))
            values = set(payload_filter_item_d["values"])
            if not values:
                logger.warning("Payload filter item without values")
                continue
            self.items.append((attribute, operator, values))
        self.items.sort()

    def test_event_payload(self, payload):
        for payload_attribute, operator, filter_value_set in self.items:
            payload_value_set = set(get_flattened_payload_values(payload, payload_attribute.split(".")))
            common_values = filter_value_set & payload_value_set
            if (operator == self.IN and not common_values) or (operator == self.NOT_IN and common_values):
                # AND: all items of a payload filter must match
                return False
        return True

    def items_display(self):
        return [(attribute, "=" if operator == "IN" else "!=", sorted(values))
                for attribute, operator, values in self.items]


class PayloadFilterItemSerializer(serializers.Serializer):
    attribute = serializers.CharField()
    operator = serializers.ChoiceField(
        choices=PayloadFilter.operator_choices
    )
    values = serializers.ListField(
        child=serializers.CharField()
    )


class PayloadFilterSerializer(serializers.ListField):
    child = PayloadFilterItemSerializer()


class FiltersSerializer(serializers.Serializer):
    inventory = serializers.ListField(
        child=InventoryFilterSerializer(),
        required=False
    )
    metadata = serializers.ListField(
        child=MetadataFilterSerializer(),
        required=False
    )
    payload = serializers.ListField(
        child=PayloadFilterSerializer(),
        required=False,
    )


class ProbeSerializer(serializers.Serializer):
    filters = FiltersSerializer(required=False)
    incident_severity = serializers.ChoiceField(Severity.choices(), allow_null=True, required=False)


class Probe:
    serializer_class = ProbeSerializer
    model_display = "events"
    create_url = reverse_lazy("probes:create")
    template_name = "probes/probe.html"

    def __init__(self, source):
        self.source = source
        self.pk = source.pk
        self.status = source.status
        self.name = source.name
        self.slug = source.slug
        self.description = source.description
        self.created_at = source.created_at
        self.load(source.body)

    def __eq__(self, other):
        if isinstance(other, Probe):
            return self.source == other.source
        return False

    # methods to load the ProbeSource.body

    def load(self, data):
        self.loaded = False
        self.syntax_errors = None
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            self.load_actions()
            self.load_validated_data(serializer.validated_data)
            self.loaded = True
        else:
            logger.warning("Invalid source body for probe %s", self.pk)
            self.syntax_errors = serializer.errors

    def load_actions(self):
        self.loaded_actions = []
        if not self.source.pk:
            return
        for action in self.source.actions.all():
            try:
                self.loaded_actions.append(get_action_backend(action, load=True))
            except Exception:
                logger.exception("Could not load action '%s'. Ignored", action)

    def load_filter_section(self, section, filter_class, filter_data_list):
        setattr(self, "{}_filters".format(section),
                [filter_class(filter_data)
                 for filter_data in filter_data_list])

    def load_filters(self, validated_data):
        filters = validated_data.get("filters", {})
        # inventory
        self.load_filter_section("inventory", InventoryFilter, filters.get("inventory", []))
        # payload
        payload_filter_data_list = filters.get("payload", [])
        self.load_filter_section("payload", PayloadFilter, payload_filter_data_list)
        # metadata
        metadata_filter_data_list = filters.get("metadata", [])
        self.load_filter_section("metadata", MetadataFilter, metadata_filter_data_list)

    def load_validated_data(self, validated_data):
        self.load_filters(validated_data)
        self.incident_severity = validated_data.get("incident_severity")

    # methods used in the ProbeSource

    def get_event_type_classes(self):
        event_type_classes = []
        if self.loaded:
            for metadata_filter in self.metadata_filters:
                event_type_classes.extend(metadata_filter.get_event_type_classes())
        return sorted(set(event_type_classes),
                      key=lambda et: et.get_event_type_display())

    # filtering methods

    # machine -> probes filtering

    def test_machine(self, meta_machine):
        """
        Test if the machine is a match for the inventory filters.
        """
        if not self.loaded:
            return False
        if not self.inventory_filters:
            return True
        for inventory_filter in self.inventory_filters:
            if inventory_filter.test_machine(meta_machine):
                # no need to check the other filters (OR)
                return True
        return False

    # event -> probes filtering

    def _test_event_metadata(self, metadata):
        if not self.metadata_filters:
            return True
        for metadata_filter in self.metadata_filters:
            if metadata_filter.test_event_metadata(metadata):
                # no need to check the other filters (OR)
                return True
        return False

    def _test_event_payload(self, payload):
        if not self.payload_filters:
            return True
        for payload_filter in self.payload_filters:
            if payload_filter.test_event_payload(payload):
                # no need to check the other filters (OR)
                return True
        return False

    def test_event(self, event):
        """
        Test if the event is a match for this probe.

        The probe sub classes can extend the tests.
        """
        if not self.loaded:
            return False
        metadata = event.metadata
        if metadata.machine_serial_number and not self.test_machine(metadata.machine):
            return False
        if not self._test_event_metadata(metadata):
            return False
        if not self._test_event_payload(event.payload):
            return False
        return True

    def get_matching_event_incident_update(self, matching_event):
        return ProbeIncident.build_incident_update(self)

    # serialize

    def serialize_for_event_metadata(self):
        return {"pk": self.pk, "name": self.name}
