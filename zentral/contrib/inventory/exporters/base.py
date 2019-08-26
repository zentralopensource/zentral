import copy
import logging
from zentral.contrib.inventory.utils import MSQuery, BundleFilter

logger = logging.getLogger("zentral.contrib.inventory.exporters.base")


class BaseExporter:
    def __init__(self, config_d, quiet=True):
        if not hasattr(self, 'name'):
            self.name = self.__module__.split('.')[-1]
        self.config_d = copy.deepcopy(config_d)
        self.config_d.pop('backend')
        self.bundle_ids = self.config_d.get("bundle_ids", [])
        self.bundle_names = self.config_d.get("bundle_names", [])
        self.quiet = quiet

    def get_ms_query(self):
        ms_query = MSQuery()
        for bundle_id in self.bundle_ids:
            ms_query.add_filter(BundleFilter, bundle_id=bundle_id)
        for bundle_name in self.bundle_names:
            ms_query.add_filter(BundleFilter, bundle_name=bundle_name)
        return ms_query
