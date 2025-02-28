from django.db import connection
from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from zentral.conf import settings


def osx_app_count(source_names, bundle_ids=None, bundle_names=None):
    assert bundle_ids is not None or bundle_names is not None
    query_args = [tuple(n.lower() for n in source_names)]
    bundle_filters = []
    if bundle_ids:
        bundle_filters.append("a.bundle_id in %s")
        query_args.append(tuple(i for i in bundle_ids))
    if bundle_names:
        bundle_filters.append("a.bundle_name in %s")
        query_args.append(tuple(n for n in bundle_names))
    serialized_bundle_filters = " OR ".join(bundle_filters)
    if len(bundle_filters) > 1:
        serialized_bundle_filters = f"({serialized_bundle_filters})"
    query = (
        "with all_app_instances as ("
        "  select a.bundle_name as name, a.bundle_version_str as version, s.id as source_id, s.name as source_name,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_osxapp as a"
        "  join inventory_osxappinstance as ai on (ai.app_id = a.id)"
        "  join inventory_machinesnapshot_osx_app_instances as msai on (msai.osxappinstance_id = ai.id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msai.machinesnapshot_id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        f"  where LOWER(s.name) in %s and {serialized_bundle_filters}"
        ") select name, version, source_id, source_name,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_app_instances "
        "group by name, version, source_id, source_name"
    )
    cursor = connection.cursor()
    cursor.execute(query, query_args)
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def program_count(source_names, program_names):
    query = (
        "with all_program_instances as ("
        "  select p.name, p.version, s.id as source_id, s.name as source_name,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_program as p"
        "  join inventory_programinstance as pi on (pi.program_id = p.id)"
        "  join inventory_machinesnapshot_program_instances as mspi on (mspi.programinstance_id = pi.id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = mspi.machinesnapshot_id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        "  and p.name in %s"
        ") select name, version, source_id, source_name,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_program_instances "
        "group by name, version, source_id, source_name"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names),
                           tuple(n for n in program_names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def android_app_count(source_names, names):
    query = (
        "with all_android_apps as ("
        "  select a.display_name as name, a.version_name as version, s.id as source_id, s.name as source_name,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_androidapp as a"
        "  join inventory_machinesnapshot_android_apps as msaa on (msaa.androidapp_id = a.id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msaa.machinesnapshot_id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        "  and a.display_name in %s"
        ") select name, version, source_id, source_name,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_android_apps "
        "group by name, version, source_id, source_name"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names),
                           tuple(n for n in names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def deb_package_count(source_names, package_names):
    query = (
        "with all_deb_packages as ("
        "  select d.name, d.version, s.id as source_id, s.name as source_name, ms.type machine_type,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_debpackage as d"
        "  join inventory_machinesnapshot_deb_packages as msdp on (msdp.debpackage_id = d.id)"
        "  join inventory_machinesnapshot as ms on (ms.id = msdp.machinesnapshot_id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        "  and d.name in %s"
        ") select name, version, source_id, source_name, machine_type,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_deb_packages "
        "group by name, version, source_id, source_name, machine_type"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names),
                           tuple(n for n in package_names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def ios_app_count(source_names, names):
    query = (
        "with all_ios_apps as ("
        "  select a.name, a.version, s.id as source_id, s.name as source_name,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_iosapp as a"
        "  join inventory_machinesnapshot_ios_apps as msia on (msia.iosapp_id = a.id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msia.machinesnapshot_id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        "  and a.name in %s"
        ") select name, version, source_id, source_name,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_ios_apps "
        "group by name, version, source_id, source_name"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names),
                           tuple(n for n in names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def os_version_count(source_names):
    query = (
        "with all_os_versions as ("
        "  select o.name, o.major, o.minor, o.patch, o.build, o.version,"
        "  s.id as source_id, s.name as source_name,"
        "  ms.platform as platform,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_osversion as o"
        "  join inventory_machinesnapshot as ms on (ms.os_version_id = o.id)"
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        ") select name, major, minor, patch, build, version, source_id, source_name, platform,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_os_versions "
        "group by name, major, minor, patch, build, version, source_id, source_name, platform"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


def active_machines_count(source_names):
    query = (
        "with all_active_machines as ("
        "  select ms.platform, ms.type as machine_type, s.id as source_id, s.name as source_name,"
        "  date_part('days', now() - cms.last_seen) as age"
        "  from inventory_currentmachinesnapshot as cms"
        "  join inventory_machinesnapshot as ms on (cms.machine_snapshot_id = ms.id)"
        "  join inventory_source as s on (s.id = cms.source_id)"
        "  where LOWER(s.name) in %s"
        ") select platform, machine_type, source_id, source_name,"
        'count(*) filter (where age < 1) as "1",'
        'count(*) filter (where age < 7) as "7",'
        'count(*) filter (where age < 14) as "14",'
        'count(*) filter (where age < 30) as "30",'
        'count(*) filter (where age < 45) as "45",'
        'count(*) filter (where age < 90) as "90",'
        'count(*) as "+Inf" '
        "from all_active_machines "
        "group by platform, machine_type, source_id, source_name"
    )
    cursor = connection.cursor()
    cursor.execute(query, [tuple(n.lower() for n in source_names)])
    columns = [col.name for col in cursor.description]
    for row in cursor.fetchall():
        yield dict(zip(columns, row))


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
            labels = {k: r[k] or "" for k in ("name", "version", "source_name", "source_id")}
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
            labels = {k: r[k] or "" for k in ("name", "version", "source_name", "source_id", "machine_type")}
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
            labels = {k: r[k] or "" for k in ("name", "version", "source_name", "source_id")}
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
                k: "" if r[k] is None else r[k]
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
            labels = {k: r[k] or "" for k in ('name', 'version', 'source_name', 'source_id')}
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
            labels = {k: r[k] or "" for k in ('name', 'version', 'source_name', 'source_id')}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_active_machines(self):
        if not self.all_source_names:
            return
        g = Gauge('zentral_inventory_active_machines_bucket', 'Zentral inventory active machines',
                  ['platform', 'machine_type', 'source_id', 'source_name', 'le'],
                  registry=self.registry)
        for r in active_machines_count(self.all_source_names):
            labels = {k: r[k] or "" for k in ('platform', 'machine_type', 'source_name', 'source_id')}
            for le in ("1", "7", "14", "30", "45", "90", "+Inf"):
                g.labels(le=le, **labels).set(r[le])

    def add_machine_tags(self):
        g = Gauge('zentral_inventory_machine_tags', 'Zentral machine tags',
                  ['taxonomy', 'tag'],
                  registry=self.registry)
        with connection.cursor() as cursor:
            cursor.execute(
                "select tx.name, t.name, count(*) "
                "from inventory_machinetag mt "
                "join inventory_tag t on (mt.tag_id = t.id) "
                "left join inventory_taxonomy tx on (t.taxonomy_id = tx.id) "
                "group by tx.name, t.name"
            )
            for taxonomy, tag, count in cursor.fetchall():
                g.labels(
                    taxonomy=taxonomy or "_",
                    tag=tag,
                ).set(count)

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
        self.add_machine_tags()
