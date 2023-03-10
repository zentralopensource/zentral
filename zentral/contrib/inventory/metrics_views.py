from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from zentral.conf import settings
from .utils import (active_machines_count, android_app_count, deb_package_count, ios_app_count,
                    osx_app_count, os_version_count, program_count)


class MetricsView(BasePrometheusMetricsView):
    def add_android_apps(self):
        options = self.metrics_options.get("android_apps", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_android_apps_bucket',  'Zentral inventory Android apps',
                  ['name', 'version', 'source_name', 'source_id', 'le'],
                  registry=self.registry)
        for r in android_app_count(sources, names):
            labels = {k: r[k] for k in ("name", "version", "source_name", "source_id")}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_deb_packages(self):
        options = self.metrics_options.get("deb_packages", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_deb_packages_bucket',  'Zentral inventory Debian packages',
                  ['name', 'version', 'source_name', 'source_id', 'machine_type', 'le'],
                  registry=self.registry)
        for r in deb_package_count(sources, names):
            labels = {k: r[k] for k in ("name", "version", "source_name", "source_id", "machine_type")}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_ios_apps(self):
        options = self.metrics_options.get("ios_apps", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_ios_apps_bucket',  'Zentral inventory iOS apps',
                  ['name', 'version', 'source_name', 'source_id', 'le'],
                  registry=self.registry)
        for r in ios_app_count(sources, names):
            labels = {k: r[k] for k in ("name", "version", "source_name", "source_id")}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_os_versions(self):
        options = self.metrics_options.get("os_versions", {})
        sources = options.get("sources")
        if not sources:
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_os_versions_bucket', 'Zentral inventory OS Versions',
                  ['name',
                   'major', 'minor', 'patch',
                   'build', 'version',
                   'source_id',  'source_name',
                   'platform',
                   'le'],
                  registry=self.registry)
        for r in os_version_count(sources):
            labels = {
                k: r[k]
                for k in ('name',
                          'major', 'minor', 'patch',
                          'build', 'version',
                          'source_id',  'source_name',
                          'platform')
            }
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_osx_apps(self):
        options = self.metrics_options.get("osx_apps", {})
        sources = options.get("sources")
        bundle_ids = options.get("bundle_ids", [])
        bundle_names = options.get("bundle_names", [])
        if not sources or (not bundle_ids and not bundle_names):
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_osx_apps_bucket',  'Zentral inventory OSX apps',
                  ['name', 'version', 'source_name', 'source_id', 'le'],
                  registry=self.registry)
        for r in osx_app_count(sources, bundle_ids, bundle_names):
            labels = {k: r[k] for k in ('name', 'version', 'source_name', 'source_id')}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_programs(self):
        options = self.metrics_options.get("programs", {})
        sources = options.get("sources")
        names = options.get("names")
        if not sources or not names:
            return
        self.all_source_names.update(sources)
        g = Gauge('zentral_inventory_programs_bucket',  'Zentral inventory programs',
                  ['name', 'version', 'source_name', 'source_id', 'le'],
                  registry=self.registry)
        for r in program_count(sources, names):
            labels = {k: r[k] for k in ('name', 'version', 'source_name', 'source_id')}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_active_machines(self):
        if not self.all_source_names:
            return
        g = Gauge('zentral_inventory_active_machines_bucket', 'Zentral inventory active machines',
                  ['platform', 'machine_type', 'source_id', 'source_name', 'le'],
                  registry=self.registry)
        for r in active_machines_count(self.all_source_names):
            labels = {k: r[k] for k in ('platform', 'machine_type', 'source_name', 'source_id')}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def populate_registry(self):
        self.metrics_options = settings["apps"]["zentral.contrib.inventory"].get("metrics_options", {})
        self.all_source_names = set([])
        self.add_android_apps()
        self.add_deb_packages()
        self.add_ios_apps()
        self.add_os_versions()
        self.add_osx_apps()
        self.add_programs()
        self.add_active_machines()
