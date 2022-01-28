from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from zentral.conf import settings
from .utils import deb_package_count, osx_app_count, os_version_count, program_count


class MetricsView(BasePrometheusMetricsView):
    def add_deb_packages(self):
        options = self.metrics_options.get("deb_packages", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        g = Gauge('zentral_inventory_deb_packages',  'Zentral inventory Debian packages',
                  ['name', 'version', 'source_name', 'source_id'],
                  registry=self.registry)
        for r in deb_package_count(sources, names):
            count = r.pop("count")
            g.labels(**r).set(count)

    def add_os_versions(self):
        options = self.metrics_options.get("os_versions", {})
        sources = options.get("sources")
        if not sources:
            return
        g = Gauge('zentral_inventory_os_versions', 'Zentral inventory OS Versions',
                  ['name', 'major', 'minor', 'patch', 'build', 'source_id',  'source_name'],
                  registry=self.registry)
        for r in os_version_count(sources):
            count = r.pop('count')
            g.labels(**r).set(count)

    def add_osx_apps(self):
        options = self.metrics_options.get("osx_apps", {})
        sources = options.get("sources")
        bundle_ids = options.get("bundle_ids")
        if not sources or not bundle_ids:
            return
        g = Gauge('zentral_inventory_osx_apps',  'Zentral inventory OSX apps',
                  ['name', 'version', 'source_name', 'source_id'],
                  registry=self.registry)
        for r in osx_app_count(sources, bundle_ids):
            count = r.pop("count")
            g.labels(**r).set(count)

    def add_programs(self):
        options = self.metrics_options.get("programs", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        g = Gauge('zentral_inventory_programs',  'Zentral inventory programs',
                  ['name', 'version', 'source_name', 'source_id'],
                  registry=self.registry)
        for r in program_count(sources, names):
            count = r.pop("count")
            g.labels(**r).set(count)

    def populate_registry(self):
        self.metrics_options = settings["apps"]["zentral.contrib.inventory"].get("metrics_options", {})
        self.add_deb_packages()
        self.add_os_versions()
        self.add_osx_apps()
        self.add_programs()
