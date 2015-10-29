class BaseEventStore(object):
    def __init__(self, config_d):
        self.name = config_d['store_name']
        self.frontend = config_d.get('frontend', False)

    def get_osquery_probe_visu_url(self, probe_name):
        return None

    def get_osquery_query_visu_url(self, query_name):
        return None
