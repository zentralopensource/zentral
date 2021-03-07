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
        self.frontend = config_d.get('frontend', False)
        self.configured = False
        self.batch_size = min(self.max_batch_size, max(config_d.get("batch_size") or 1, 1))

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
