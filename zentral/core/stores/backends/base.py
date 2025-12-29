from rest_framework import serializers
from zentral.core.events.filter import EventFilterSet
from zentral.utils.backend_model import Backend


class BaseStore(Backend):
    read_only = False  # if read only, we do not need a store worker
    batch_size = 1
    max_batch_age_seconds = 60
    concurrency = 1
    machine_events = False
    machine_events_url = False
    last_machine_heartbeats = False
    object_events = False
    object_events_url = False
    probe_events = False
    probe_events_url = False

    def __init__(self, instance, load=True):
        self.slug = instance.slug
        super().__init__(instance, load)

    def load(self):
        super().load()
        self.admin_console = self.instance.admin_console
        self.events_url_authorized_roles = list(self.instance.events_url_authorized_roles.all())
        self.events_url_authorized_role_pk_set = set(r.pk for r in self.events_url_authorized_roles)
        self.event_filter_set = EventFilterSet.from_mapping(self.instance.event_filters)
        self.configured = False

    def is_serialized_event_included(self, serialized_event):
        return self.event_filter_set.match_serialized_event(serialized_event)

    def wait_and_configure(self):
        self.configured = True

    def wait_and_configure_if_necessary(self):
        if not self.configured:
            self.wait_and_configure()

    # machine events

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return [], None

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        return {}

    def get_last_machine_heartbeats(self, serial_number, from_dt):
        return {}

    def get_machine_events_url(self, serial_number, from_dt, to_dt=None, event_type=None):
        return None

    # object events

    def fetch_object_events(self, key, val, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return [], None

    def get_aggregated_object_event_counts(self, key, val, from_dt, to_dt=None):
        return {}

    def get_object_events_url(self, key, val, from_dt, to_dt=None, event_type=None):
        return None

    # probe events

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return [], None

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        return {}

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return None

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag):
        return []


# Serializers


class AWSAuthSerializer(serializers.Serializer):
    region_name = serializers.CharField(min_length=1)
    aws_access_key_id = serializers.CharField(required=False, allow_null=True)
    aws_secret_access_key = serializers.CharField(required=False, allow_null=True)

    def validate(self, data):
        aws_access_key_id = data.get("aws_access_key_id")
        aws_secret_access_key = data.get("aws_secret_access_key")
        if aws_access_key_id and not aws_secret_access_key:
            raise serializers.ValidationError({"aws_secret_access_key": "This field is required"})
        elif aws_secret_access_key and not aws_access_key_id:
            raise serializers.ValidationError({"aws_access_key_id": "This field is required"})
        return data


# Utils


def serialize_needles(metadata):
    needles = []  # for serial_number, object, probe lookups
    serial_number = metadata.get("machine_serial_number")
    if serial_number:
        needles.append(f"_s:{serial_number}")
    for obj_k, obj_vals in metadata.get("objects", {}).items():
        for obj_val in obj_vals:
            needles.append(f"_o:{obj_k}:{obj_val}")
    for probe in metadata.get("probes", []):
        needles.append(f"_p:{probe['pk']}")
    return needles
