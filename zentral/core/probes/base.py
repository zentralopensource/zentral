import collections
import collections.abc
import copy
import logging
from django.urls import reverse_lazy
from django.utils.functional import cached_property
from rest_framework import serializers
from zentral.contrib.inventory.conf import (PLATFORM_CHOICES, PLATFORM_CHOICES_DICT,
                                            TYPE_CHOICES, TYPE_CHOICES_DICT)
from zentral.core.actions import actions as available_actions
from zentral.core.events import event_types
from zentral.core.stores import stores
from . import register_probe_class

logger = logging.getLogger('zentral.core.probes.base')


class InventoryFilter(object):
    def __init__(self, **kwargs):
        for attr in ("meta_business_unit_ids", "tag_ids", "platforms", "types"):
            setattr(self, attr, set(kwargs.get(attr, [])))

    def test_machine(self, meta_machine):
        if self.meta_business_unit_ids and not self.meta_business_unit_ids & meta_machine.meta_business_unit_id_set:
            return False
        if self.tag_ids and not self.tag_ids & meta_machine.tag_id_set:
            return False
        if self.platforms and meta_machine.platform not in self.platforms:
            return False
        if self.types and meta_machine.type not in self.types:
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
        for key, val in data.items():
            if val:
                return data
        raise serializers.ValidationError("No business units, tags, platforms or types")


class MetadataFilter(object):
    def __init__(self, event_types=None, event_tags=None):
        if event_types is None:
            event_types = []
        self.event_types = set(event_types)
        if event_tags is None:
            event_tags = []
        self.event_tags = set(event_tags)

    def test_event_metadata(self, metadata):
        if self.event_types and metadata.event_type not in self.event_types:
            return False
        if self.event_tags and not set(metadata.tags) & self.event_tags:
            return False
        return True

    def get_event_type_classes(self):
        l = []
        for et in self.event_types:
            try:
                et = event_types[et]
            except KeyError:
                logger.warning("Unknown event type %s in metadata filter", et)
            else:
                l.append(et)
        l.sort(key=lambda et: et.get_event_type_display())
        return l

    def get_event_types_display(self):
        return ", ".join(et.get_event_type_display()
                         for et in self.get_event_type_classes())

    def get_event_tags_display(self):
        return ", ".join(sorted(t.replace("_", " ")
                                for t in self.event_tags))


class MetadataFiltersSerializer(serializers.Serializer):
    event_types = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    event_tags = serializers.ListField(
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
                yield from val
            else:
                yield val
        else:
            yield from get_flattened_payload_values(val, attrs)
    else:
        logger.warning("Wrong payload filter attribute %s", attrs)


class PayloadFilter(object):
    def __init__(self, **kwargs):
        self.items = {k: set(v) for k, v in kwargs.items()}

    def test_event_payload(self, payload):
        for payload_attribute, filter_value_set in self.items.items():
            payload_value_set = set(get_flattened_payload_values(payload, payload_attribute.split(".")))
            if not payload_value_set & filter_value_set:
                return False
        return True

    def items_display(self):
        return sorted((k, sorted(v)) for k, v in self.items.items())


class PayloadFilterSerializer(serializers.DictField):
    child = serializers.ListField(
        child=serializers.CharField()
    )


class FiltersSerializer(serializers.Serializer):
    inventory = serializers.ListField(
        child=InventoryFilterSerializer(),
        required=False
    )
    metadata = serializers.ListField(
        child=MetadataFiltersSerializer(),
        required=False
    )
    payload = serializers.ListField(
        child=PayloadFilterSerializer(),
        required=False
    )


class ActionsSerializer(serializers.DictField):
    child = serializers.JSONField()


class BaseProbeSerializer(serializers.Serializer):
    filters = FiltersSerializer(required=False)
    actions = ActionsSerializer(required=False)


class BaseProbe(object):
    serializer_class = BaseProbeSerializer
    model_display = "events"
    forced_event_type = None
    create_url = reverse_lazy("probes:create")
    template_name = "core/probes/probe.html"
    can_edit_payload_filters = True

    def __init__(self, source):
        self.source = source
        self.pk = source.pk
        self.status = source.status
        self.name = source.name
        self.slug = source.slug
        self.description = source.description
        self.created_at = source.created_at
        self.can_edit_metadata_filters = self.forced_event_type is None
        self.load(source.body)

    # methods to load the ProbeSource.body

    def load(self, data):
        self.loaded = False
        self.syntax_errors = None
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            self.load_validated_data(serializer.validated_data)
            self.loaded = True
        else:
            logger.warning("Invalid source body for probe %s", self.pk)
            self.syntax_errors = serializer.errors

    def load_actions(self, validated_data):
        self.actions = []
        actions = validated_data.get("actions")
        if not actions:
            return
        for action_name, action_config_d in actions.items():
            try:
                self.actions.append((available_actions[action_name],
                                     action_config_d))
            except KeyError:
                logger.warning("Unknown action '%s'. Ignored", action_name)

    def load_filter_section(self, section, filter_class, filter_data_list):
        setattr(self, "{}_filters".format(section),
                [filter_class(**filter_data)
                 for filter_data in filter_data_list])

    def load_filters(self, validated_data):
        filters = validated_data.get("filters", {})
        # inventory
        self.load_filter_section("inventory", InventoryFilter, filters.get("inventory", []))
        # payload
        payload_filter_data_list = filters.get("payload", [])
        if self.can_edit_payload_filters:
            self.load_filter_section("payload", PayloadFilter, payload_filter_data_list)
        else:
            if payload_filter_data_list:
                logger.warning("Payload filters in probe %s with can_edit_payload_filters == False", self.pk)
            # the sub classes with can_edit_payload_filters == False must override this
            self.payload_filters = []
        # metadata
        metadata_filter_data_list = filters.get("metadata", [])
        if not self.forced_event_type:
            self.load_filter_section("metadata", MetadataFilter, metadata_filter_data_list)
        else:
            if metadata_filter_data_list:
                logger.warning("Metadata filters in probe %s with force_event_type", self.pk)
            self.metadata_filters = [MetadataFilter(event_types=[self.forced_event_type])]

    # load_validated_data must be extended in the sub-classes
    # to load the rest of the probe source
    def load_validated_data(self, validated_data):
        self.load_filters(validated_data)
        self.load_actions(validated_data)

    # methods used in the ProbeSource

    @classmethod
    def get_model(cls):
        return cls.__name__

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
        if self.forced_event_type:
            if event.event_type != self.forced_event_type:
                return False
        elif not self._test_event_metadata(metadata):
            return False
        if not self._test_event_payload(event.payload):
            return False
        return True

    def get_extra_links(self):
        return []

    # links to the matching events in the event stores
    def get_extra_event_search_dict(self):
        return {}

    def get_store_links(self, **search_dict):
        if not search_dict:
            search_dict = self.get_extra_event_search_dict()
        links = []
        for store in stores:
            url = store.get_vis_url(self, **search_dict)
            if url:
                links.append((store.name, url))
        links.sort()
        return links

    def not_configured_actions(self):
        """return a list of available actions not configured in the probe."""
        configured_actions = {action.name for action, _ in self.actions}
        l = [action
             for action_name, action in available_actions.items()
             if action_name not in configured_actions]
        l.sort(key=lambda action: action.name)
        return l

    # export method for probe sharing

    def export(self):
        body = copy.deepcopy(self.source.body)
        if "actions" in body:
            del body["actions"]
        body_filters = body.get("filters", {})
        if "inventory" in body_filters:
            del body_filters["inventory"]
        if not self.can_edit_metadata_filters and "metadata" in body_filters:
            del body_filters["metadata"]
        if not self.can_edit_payload_filters and "payload" in body_filters:
            del body_filters["payload"]
        d = {"name": self.name,
             "model": self.get_model(),
             "body": body}
        if self.description:
            d["description"] = self.description
        return d

    # aggregations

    def get_aggregations(self):
        aggs = collections.OrderedDict([("created_at",
                                        {"type": "date_histogram",
                                         "interval": "day",
                                         "bucket_number": 31,
                                         "label": "Events"})])
        event_type_classes = self.get_event_type_classes()
        if len(event_type_classes) == 1:
            event_type_class = event_type_classes[0]
            for field, aggregation in event_type_class.get_payload_aggregations():
                aggs[field] = aggregation
        else:
            aggs["event_type"] = {
                "type": "terms",
                "bucket_number": len(event_types),
                "label": "Event types",
            }
        return aggs


register_probe_class(BaseProbe)
