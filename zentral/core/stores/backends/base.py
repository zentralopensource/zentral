class BaseEventStore(object):
    def __init__(self, config_d):
        self.name = config_d['store_name']
        self.frontend = config_d.get('frontend', False)
        self.configured = False

    def wait_and_configure(self):
        self.configured = True

    def wait_and_configure_if_necessary(self):
        if not self.configured:
            self.wait_and_configure()

    def probe_events_fetch(self, probe, offset=0, limit=0, **search_dict):
        return []

    def probe_events_count(self, probe, **search_dict):
        return 0

    def probe_events_aggregations(self, probe, **search_dict):
        return {}

    def get_vis_url(self, probe, **search_dict):
        return None

    def get_app_hist_data(self, interval, bucket_number, tag=None, event_type=None):
        return []
