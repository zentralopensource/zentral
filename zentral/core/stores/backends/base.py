import warnings
from zentral.core.events.filter import EventFilterSet


class BaseEventStore(object):
    read_only = False  # if read only, we do not need a store worker
    max_batch_size = 1
    max_concurrency = 1
    machine_events = False
    machine_events_url = False
    last_machine_heartbeats = False
    object_events = False
    object_events_url = False
    probe_events = False
    probe_events_url = False
    probe_events_aggregations = False

    def __init__(self, config_d):
        self.name = config_d['store_name']
        # list of group names
        # members of those groups will have access to the events URLs
        self.events_url_authorized_groups = set(config_d.get("events_url_authorized_groups", []))
        self.frontend = config_d.get('frontend', False)
        self.configured = False
        self.batch_size = min(self.max_batch_size, max(config_d.get("batch_size") or 1, 1))
        self.concurrency = min(self.max_concurrency, max(config_d.get("concurrency") or 1, 1))
        self.event_filter_set = EventFilterSet.from_mapping(config_d)
        # legacy included / excluded event types attrs ?
        # TODO remove later
        if not self.event_filter_set:
            filter_set_m = {}
            excluded_event_types = config_d.get("excluded_event_types")
            if excluded_event_types:
                warnings.warn(
                    "excluded_event_types is deprecated and will be removed soon. "
                    "Use excluded_event_filters instead.",
                    DeprecationWarning, stacklevel=2,
                )
                filter_set_m["excluded_event_filters"] = [{"event_type": excluded_event_types}]
            included_event_types = config_d.get("included_event_types")
            if included_event_types:
                warnings.warn(
                    "included_event_types is deprecated and will be removed soon. "
                    "Use included_event_filters instead.",
                    DeprecationWarning, stacklevel=2,
                )
                filter_set_m["included_event_filters"] = [{"event_type": included_event_types}]
            if filter_set_m:
                self.event_filter_set = EventFilterSet.from_mapping(filter_set_m)

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

    def get_probe_events_aggregations(self, probe, from_dt, to_dt=None):
        return {}

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return None

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag):
        return []
