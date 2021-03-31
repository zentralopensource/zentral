class BaseEventStore(object):
    max_batch_size = 1
    machine_events = False
    machine_events_url = False
    last_machine_heartbeats = False
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
        # excluded / included event types
        for prefix in ("excluded", "included"):
            attr = f"{prefix}_event_types"
            val = config_d.get(attr)
            if val:
                val = set(val)
            else:
                val = None
            setattr(self, attr, val)

    def is_event_type_included(self, event_type):
        return (
            (not self.excluded_event_types or event_type not in self.excluded_event_types)
            and (not self.included_event_types or event_type in self.included_event_types)
        )

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

    # probe events

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        return [], None

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        return {}

    def get_probe_events_aggregations(self, probe, from_dt, to_dt=None):
        return {}

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return None

    # incident events

    def incident_events_fetch(self, incident, offset=0, limit=0):
        return []

    def incident_events_count(self, incident):
        return 0

    def get_incident_vis_url(self, incident):
        return None

    # zentral apps data

    def get_app_hist_data(self, interval, bucket_number, tag=None, event_type=None):
        return []
