class BaseEventStore(object):
    def __init__(self, config_d):
        self.name = config_d['store_name']
        self.frontend = config_d.get('frontend', False)

    def get_visu_url(self, search_dict):
        return None

    def get_visu_url(self, search_dict):
        return None
