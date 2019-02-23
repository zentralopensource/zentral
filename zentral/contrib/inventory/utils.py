from collections import OrderedDict
from datetime import datetime
import logging
from django.db import connection
from django.db.models import Count
from prometheus_client import (CollectorRegistry, Gauge,  # NOQA
                               generate_latest, CONTENT_TYPE_LATEST as prometheus_metrics_content_type)
from zentral.utils.charts import make_dataset
from zentral.utils.json import log_data
from .conf import PLATFORM_CHOICES_DICT, TYPE_CHOICES_DICT
from .events import (post_enrollment_secret_verification_failure, post_enrollment_secret_verification_success,
                     post_inventory_events)
from .exceptions import EnrollmentSecretVerificationFailed
from .models import EnrollmentSecret, MachineSnapshot, MachineSnapshotCommit, MetaMachine

logger = logging.getLogger("zentral.contrib.inventory.utils")


class BaseMSFilter:
    title = "Untitled"
    query_kwarg = None
    many = False
    non_grouping_expression = None
    expression = None
    grouping_set = None

    def __init__(self, idx, query_dict):
        self.idx = idx
        self.query_dict = query_dict
        self.value = query_dict.get(self.get_query_kwarg())
        self.grouping_alias = "fg{}".format(idx)

    def get_query_kwarg(self):
        return self.query_kwarg

    def get_expressions(self, grouping=False):
        if grouping:
            if self.grouping_set:
                yield "grouping({}) as {}".format(self.grouping_set[0], self.grouping_alias)
            if self.expression:
                yield self.expression
        elif self.expression:
            if not self.many:
                yield self.expression
            else:
                if "as" in self.expression:
                    expression, alias = self.expression.split(" as ")
                    expression = "json_agg({})".format(expression)
                else:
                    expression = self.expression
                    alias = None
                yield " as ".join(e for e in (expression, alias) if e)
        elif self.non_grouping_expression:
            yield self.non_grouping_expression

    def get_group_by(self):
        if self.many:
            return None
        elif self.grouping_set:
            return self.grouping_set[-1]
        elif self.non_grouping_expression:
            return self.non_grouping_expression

    def joins(self):
        return []

    def wheres(self):
        return []

    def where_args(self):
        return []

    # process grouping results

    def filter_grouping_results(self, grouping_results):
        for gr in grouping_results:
            if gr.get(self.grouping_alias) == 0:
                yield gr

    def grouping_value_from_grouping_result(self, grouping_result):
        if not self.grouping_set:
            return
        return grouping_result.get(self.grouping_set[-1].split(".")[-1])

    def label_for_grouping_value(self, grouping_value):
        return str(grouping_value) if grouping_value else "-"

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        return grouping_value

    def grouping_choices_from_grouping_results(self, grouping_results):
        choices = []
        for grouping_result in self.filter_grouping_results(grouping_results):
            grouping_value = self.grouping_value_from_grouping_result(grouping_result)
            # label
            label = self.label_for_grouping_value(grouping_value)
            # query_dict
            query_dict = self.query_dict.copy()
            query_dict.pop("page", None)
            query_kwarg_value = self.query_kwarg_value_from_grouping_value(grouping_value)
            query_kwarg = self.get_query_kwarg()
            if query_dict.get(query_kwarg) == str(query_kwarg_value):
                # already filtered
                down_query_dict = None
                up_query_dict = query_dict
                up_query_dict.pop(query_kwarg, None)
            else:
                down_query_dict = query_dict
                down_query_dict[query_kwarg] = query_kwarg_value
                up_query_dict = None
            # count
            count = grouping_result["count"]
            choices.append((label, count, down_query_dict, up_query_dict))
        return choices

    # process fetching results

    def process_fetched_record(self, record):
        return


class SourceFilter(BaseMSFilter):
    title = "Sources"
    query_kwarg = "src"
    expression = "jsonb_build_object('id', src.id, 'name', src.name, 'config', src.config) as src_j"
    grouping_set = ("src.id", "src_j")

    def joins(self):
        yield "join inventory_source as src on (ms.source_id = src.id)"

    def wheres(self):
        if self.value:
            yield "src.id = %s"

    def where_args(self):
        if self.value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return "-"
        else:
            return grouping_value["name"]

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if not grouping_value:
            return None
        else:
            return grouping_value["id"]

    def process_fetched_record(self, record):
        source = record.pop("src_j", None)
        if source and source["id"]:
            record["source"] = source


class OSVersionFilter(BaseMSFilter):
    title = "OS"
    query_kwarg = "osv"
    expression = ("jsonb_build_object("
                  "'id', osv.id, "
                  "'name', osv.name, "
                  "'major', osv.major, "
                  "'minor', osv.minor, "
                  "'patch', osv.patch, "
                  "'build', osv.build) as osv_j")
    grouping_set = ("osv.id", "osv_j")

    def joins(self):
        yield "left join inventory_osversion as osv on (ms.os_version_id = osv.id)"

    def wheres(self):
        if self.value:
            yield "osv.id = %s"

    def where_args(self):
        if self.value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return "-"
        label = [grouping_value["name"]]
        label.append(".".join(str(num) for num in
                              (grouping_value.get(attr) for attr in ("major", "minor", "patch"))
                              if num is not None))
        build = grouping_value.get("build")
        if build:
            label.append("({})".format(build))
        return " ".join(e for e in label if e)

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record):
        os_version = record.pop("osv_j", None)
        if os_version and os_version["id"]:
            record["os_version"] = os_version


class MetaBusinessUnitFilter(BaseMSFilter):
    title = "Meta business units"
    query_kwarg = "mbu"
    expression = "jsonb_build_object('id', mbu.id, 'name', mbu.name) as mbu_j"
    grouping_set = ("mbu.id", "mbu_j")

    def joins(self):
        return ["left join inventory_businessunit as bu on (ms.business_unit_id = bu.id)",
                "left join inventory_metabusinessunit as mbu on (bu.meta_business_unit_id = mbu.id)"]

    def wheres(self):
        if self.value:
            yield "mbu.id = %s"

    def where_args(self):
        if self.value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return "-"
        else:
            return grouping_value["name"] or "?"

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record):
        meta_business_unit = record.pop("mbu_j", None)
        if meta_business_unit and meta_business_unit["id"]:
            record["meta_business_unit"] = meta_business_unit


class TagFilter(BaseMSFilter):
    title = "Tags"
    many = True
    query_kwarg = "t"
    expression = (
        "jsonb_build_object("
        "'id', t.id, "
        "'name', t.name, "
        "'color', t.color, "
        "'meta_business_unit', "
        "jsonb_build_object('id', tmbu.id, 'name', tmbu.name)"
        ") as tag_j"
    )
    grouping_set = ("t.id", "tag_j")

    def joins(self):
        return [("left join lateral ("
                 "select distinct * "
                 "from inventory_tag "
                 "where id in ("
                 "select mt.tag_id "
                 "from inventory_machinetag as mt "
                 "where mt.serial_number = ms.serial_number "
                 "union "
                 "select mbut.tag_id "
                 "from inventory_metabusinessunittag as mbut "
                 "join inventory_businessunit as bu on (bu.meta_business_unit_id = mbut.meta_business_unit_id) "
                 "where bu.id = ms.business_unit_id "
                 ")"
                 ") t on TRUE"),
                "left join inventory_metabusinessunit as tmbu on (tmbu.id = t.meta_business_unit_id)"]

    def wheres(self):
        if self.value:
            yield "t.id = %s"

    def where_args(self):
        if self.value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        elif gv["meta_business_unit"]["id"] is None:
            gv["meta_business_unit"] = None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return "-"
        label = grouping_value["name"] or "?"
        mbu = grouping_value.get("meta_business_unit")
        if mbu:
            mbu_name = mbu.get("name")
            if mbu_name:
                label = "{}/{}".format(mbu_name, label)
        return label

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record):
        tags = []
        for tag in record.pop("tag_j", []):
            if not tag["id"]:
                continue
            display_name = tag["name"]
            if not tag["meta_business_unit"]["id"]:
                tag["meta_business_unit"] = None
            else:
                display_name = "/".join(s for s in (tag["meta_business_unit"]["name"], display_name) if s)
            tag["display_name"] = display_name
            tags.append(tag)
        record["tags"] = tags


class BundleFilter(BaseMSFilter):
    many = True

    def __init__(self, *args, **kwargs):
        self.bundle_id = kwargs.pop("bundle_id", None)
        self.bundle_name = kwargs.pop("bundle_name", None)
        if not self.bundle_id and not self.bundle_name:
            raise ValueError("no bundle id and no bundle name")
        self.title = self.bundle_name or self.bundle_id
        super().__init__(*args, **kwargs)
        self.expression = (
            "jsonb_build_object("
            "'id', a{idx}.id, "
            "'bundle_id', a{idx}.bundle_id, "
            "'bundle_name', a{idx}.bundle_name, "
            "'bundle_version', a{idx}.bundle_version, "
            "'bundle_version_str', a{idx}.bundle_version_str"
            ") as a{idx}_j"
        ).format(idx=self.idx)
        self.grouping_set = (
            "a{idx}.id".format(idx=self.idx),
            "a{idx}_j".format(idx=self.idx)
        )

    def get_query_kwarg(self):
        return "a{}".format(self.idx)

    def joins(self):
        if self.bundle_id:
            arg = self.bundle_id
            subquery_cond = "a.bundle_id = %s"
        elif self.bundle_name:
            arg = self.bundle_name
            subquery_cond = "a.bundle_name = %s"
        yield (("left join lateral ("
                "select a.* from inventory_osxapp as a "
                "join inventory_osxappinstance as oai on (oai.app_id = a.id) "
                "join inventory_machinesnapshot_osx_app_instances as msoai on (msoai.osxappinstance_id = oai.id) "
                "where msoai.machinesnapshot_id = ms.id and {subquery_cond}"
                ") a{idx} on TRUE").format(idx=self.idx, subquery_cond=subquery_cond),
               [arg])

    def wheres(self):
        if self.value:
            yield "a{}.id = %s".format(self.idx)

    def where_args(self):
        if self.value:
            yield self.value

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return "-"
        if self.bundle_id:
            # TODO hack. Try to set a better title.
            bundle_name = grouping_value["bundle_name"]
            if bundle_name:
                self.title = bundle_name
        return " ".join(e for e in (grouping_value["bundle_name"], grouping_value["bundle_version_str"]) if e)

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record):
        osx_apps = []
        for osx_app in record.pop(self.grouping_set[-1], []):
            if not osx_app["id"]:
                continue
            osx_apps.append(osx_app)
        # TODO: verify no conflict
        record.setdefault("osx_apps", OrderedDict())[self.title] = osx_apps


class TypeFilter(BaseMSFilter):
    title = "Types"
    query_kwarg = "tp"
    expression = "ms.type"
    grouping_set = ("ms.type",)

    def wheres(self):
        if self.value:
            yield "ms.type = %s"

    def where_args(self):
        if self.value:
            yield self.value

    def label_for_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value.title()
        else:
            return "-"


class PlaformFilter(BaseMSFilter):
    title = "Platforms"
    query_kwarg = "pf"
    expression = "ms.platform"
    grouping_set = ("ms.platform",)

    def wheres(self):
        if self.value:
            yield "ms.platform = %s"

    def where_args(self):
        if self.value:
            yield self.value


class SerialNumberFilter(BaseMSFilter):
    query_kwarg = "sn"
    non_grouping_expression = "ms.serial_number"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.value:
            self.value = self.value.strip()

    def wheres(self):
        if self.value:
            yield "UPPER(ms.serial_number) LIKE UPPER(%s)"

    def where_args(self):
        if self.value:
            yield "%{}%".format(connection.ops.prep_for_like_query(self.value))

    def process_fetched_record(self, record):
        record["urlsafe_serial_number"] = MetaMachine.make_urlsafe_serial_number(record["serial_number"])


class ComputerNameFilter(BaseMSFilter):
    query_kwarg = "cn"
    non_grouping_expression = "si.computer_name"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.value:
            self.value = self.value.strip()

    def joins(self):
        yield "left join inventory_systeminfo as si on (ms.system_info_id = si.id)"

    def wheres(self):
        if self.value:
            yield "si.id is not null and si.computer_name ~* %s"

    def where_args(self):
        if self.value:
            yield self.value


class HardwareModelFilter(BaseMSFilter):
    title = "Hardware models"
    query_kwarg = "hm"
    expression = "si.hardware_model"
    grouping_set = ("si.hardware_model",)

    def joins(self):
        yield "left join inventory_systeminfo as si on (ms.system_info_id = si.id)"

    def wheres(self):
        if self.value:
            yield "si.hardware_model = %s"

    def where_args(self):
        if self.value:
            yield self.value


class DateTimeFilter(BaseMSFilter):
    query_kwarg = "dt"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.value:
            self.value = datetime.strptime("%Y-%m-%d %H:%M:%S", self.value)

    def joins(self):
        if self.value:
            yield "left join inventory_machinesnapshot as dtfms"
        else:
            yield "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"

    def wheres(self):
        if self.value:
            return ["ms.serial_number = dtfms.serial_number",
                    "ms.source_id = dtfms.source_id",
                    "ms.mt_created_at > dtfms.mt_created_at",
                    "dtfms.id is null",
                    "ms.mt_created_at < %s"]
        else:
            return []

    def where_args(self):
        if self.value:
            yield self.value


class MSQuery:
    default_filters = [
        DateTimeFilter,
        SourceFilter,
        MetaBusinessUnitFilter,
        TagFilter,
        TypeFilter,
        HardwareModelFilter,
        PlaformFilter,
        OSVersionFilter,
        SerialNumberFilter,
        ComputerNameFilter,
    ]

    def __init__(self, query_dict=None):
        self.query_dict = query_dict or {}
        self.filters = []
        for filter_class in self.default_filters:
            self.add_filter(filter_class)
        self._grouping_results = None
        self._count = None

    def add_filter(self, filter_class, **filter_kwargs):
        self.filters.append(filter_class(len(self.filters), self.query_dict, **filter_kwargs))

    # common things for grouping and fetching

    def _iter_unique_joins_with_args(self):
        unique_joins = OrderedDict()
        for f in self.filters:
            for join in f.joins():
                if isinstance(join, tuple):
                    join, join_args = join
                elif isinstance(join, str):
                    join_args = []
                else:
                    raise ValueError("invalid join")
                if join not in unique_joins:
                    unique_joins[join] = join_args
                elif unique_joins[join] != join_args:
                    raise ValueError("same join with different args exists")
        yield from unique_joins.items()

    # grouping

    def _build_grouping_query_with_args(self):
        query = ["select"]
        args = []
        # expressions
        query.append(", ".join(e for f in self.filters for e in f.get_expressions(grouping=True)))
        query.append(", count(distinct ms.serial_number)")
        # base table
        query.append("from inventory_machinesnapshot as ms")
        # joins
        for join, join_args in self._iter_unique_joins_with_args():
            query.append(join)
            args.extend(join_args)
        # wheres
        wheres = []
        for f in self.filters:
            wheres.extend(f.wheres())
            args.extend(f.where_args())
        if wheres:
            query.append("WHERE")
            query.append(" AND ".join(wheres))
        # group by sets
        grouping_sets = ["({})".format(", ".join(gsi for gsi in f.grouping_set))
                         for f in self.filters
                         if f.grouping_set]
        grouping_sets.append("()")
        query.append("GROUP BY GROUPING SETS ({})".format(", ".join(grouping_sets)))
        return "\n".join(query), args

    def _make_grouping_query(self):
        query, args = self._build_grouping_query_with_args()
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def _get_grouping_results(self):
        if self._grouping_results is None:
            self._grouping_results = self._make_grouping_query()
        return self._grouping_results

    def count(self):
        if self._count is None:
            all_grouping_aliases = [f.grouping_alias for f in self.filters]
            for grouping_result in self._get_grouping_results():
                if all(grouping_result.get(a, 1) == 1 for a in all_grouping_aliases):
                    self._count = grouping_result["count"]
                    break
            else:
                self._count = 0
        return self._count

    def grouping_choices(self):
        grouping_results = self._get_grouping_results()
        for f in self.filters:
            f_choices = f.grouping_choices_from_grouping_results(grouping_results)
            if f_choices:
                yield f, f_choices

    # fetching

    def _build_fetching_query_with_args(self, page=1, paginate_by=50):
        query = ["select"]
        args = []
        # expressions
        query.append(", ".join(e for f in self.filters for e in f.get_expressions()))
        # base table
        query.append("from inventory_machinesnapshot as ms")
        # joins
        for join, join_args in self._iter_unique_joins_with_args():
            query.append(join)
            args.extend(join_args)
        # wheres
        wheres = []
        for f in self.filters:
            wheres.extend(f.wheres())
            args.extend(f.where_args())
        if wheres:
            query.append("WHERE")
            query.append(" AND ".join(wheres))
        # group bys
        group_bys = [gb for gb in (f.get_group_by() for f in self.filters) if gb]
        if group_bys:
            query.append("GROUP BY {}".format(", ".join(group_bys)))
        query = "\n".join(query)
        limit = max(paginate_by, 1)
        args.append(limit)
        offset = max((page - 1) * limit, 0)
        args.append(offset)
        meta_query = (
            "select ms.serial_number, json_agg(row_to_json(ms.*)) as machine_snapshots "
            "from ({}) ms "
            "group by ms.serial_number "
            "order by min(ms.computer_name) asc, ms.serial_number asc "
            "limit %s offset %s"
        ).format(query)
        return meta_query, args

    def _make_fetching_query(self, page=1, paginate_by=50):
        query, args = self._build_fetching_query_with_args(page=page, paginate_by=paginate_by)
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def fetch(self, page=1, paginate_by=50):
        for record in self._make_fetching_query(page, paginate_by):
            for machine_snapshot in record["machine_snapshots"]:
                for f in self.filters:
                    f.process_fetched_record(machine_snapshot)
            yield record["serial_number"], record["machine_snapshots"]


def mbu_dashboard_machine_data(mbu):
    # platform
    platform_qs = (MachineSnapshot.objects.filter(currentmachinesnapshot__isnull=False,
                                                  business_unit__meta_business_unit=mbu,
                                                  source=mbu.dashboard_source,
                                                  platform__isnull=False)
                                          .values("platform").annotate(count=Count("platform")))
    platforms = sorted(((d["platform"], d["count"]) for d in platform_qs),
                       key=lambda t: (-1 * t[1], t[0]))
    yield "platform", "Plaforms", {
        "type": "doughnut",
        "data": {
            "labels": [PLATFORM_CHOICES_DICT.get(p, "Unknown") for p, _ in platforms],
            "datasets": [
                make_dataset([c for _, c in platforms])
            ]
        }
    }
    # type
    type_qs = (MachineSnapshot.objects.filter(currentmachinesnapshot__isnull=False,
                                              business_unit__meta_business_unit=mbu,
                                              source=mbu.dashboard_source,
                                              type__isnull=False)
                                      .values("type").annotate(count=Count("type")))
    types = sorted(((d["type"], d["count"]) for d in type_qs),
                   key=lambda t: (-1 * t[1], t[0]))
    yield "type", "Types", {
        "type": "doughnut",
        "data": {
            "labels": [TYPE_CHOICES_DICT.get(t, "Unknown") for t, _ in types],
            "datasets": [
                make_dataset([c for _, c in types])
            ]
        }
    }
    # os
    query = (
        "select osv.name as name, osv.major as major, osv.minor as minor, osv.patch as patch, "
        "count(*) as count from inventory_osversion as osv "
        "join inventory_machinesnapshot as ms on (osv.id = ms.os_version_id) "
        "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id) "
        "join inventory_businessunit as bu on (bu.id = ms.business_unit_id) "
        "where bu.meta_business_unit_id = %s and ms.source_id = %s "
        "group by osv.name, osv.major, osv.minor, osv.patch"
    )
    cursor = connection.cursor()
    cursor.execute(query, [mbu.pk, mbu.dashboard_source.pk])
    columns = [col[0] for col in cursor.description]
    os_list = []
    for row in cursor.fetchall():
        os_version = dict(zip(columns, row))
        version_str = ".".join(str(os_version[a]) for a in ("major", "minor", "patch") if os_version.get(a))
        value = " ".join(s.strip() for s in (os_version["name"], version_str) if s and s.strip())
        os_list.append((value, os_version["count"]))
    os_list.sort(key=lambda t: (-1 * t[1], t[0]))
    yield "os", "OS", {
        "type": "doughnut",
        "data": {
            "labels": [n for n, _ in os_list],
            "datasets": [
                make_dataset([c for _, c in os_list])
            ]
        }
    }


def mbu_dashboard_bundle_data(mbu):
    query = (
        "select a.bundle_id as id, a.bundle_name as name, a.bundle_version_str as version_str, foo.count as count "
        "from ("
        "  select ai.app_id, count(*) as count "
        "  from inventory_osxappinstance as ai "
        "  join inventory_machinesnapshot_osx_app_instances as msai on (msai.osxappinstance_id = ai.id) "
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msai.machinesnapshot_id) "
        "  join inventory_machinesnapshot as ms on (cms.machine_snapshot_id = ms.id) "
        "  join inventory_businessunit as bu on (ms.business_unit_id = bu.id) "
        "  where bu.meta_business_unit_id = %s and cms.source_id = %s "
        "  group by ai.app_id"
        ") as foo "
        "join inventory_osxapp as a on (foo.app_id = a.id) "
        "where a.bundle_id IN %s"
    )
    cursor = connection.cursor()
    bundle_id_tuple = tuple(mbu.dashboard_osx_app_bundle_id_list)
    cursor.execute(query, [mbu.pk, mbu.dashboard_source.pk, bundle_id_tuple])
    columns = [col[0] for col in cursor.description]
    # group versions and counts by bundle_id
    bundles = {}
    for row in cursor.fetchall():
        bundle = dict(zip(columns, row))
        if bundle["id"] not in bundles:
            bundles[bundle["id"]] = {"name": bundle["name"],
                                     "versions": {}}
        bundles[bundle["id"]]["versions"][bundle["version_str"]] = bundle["count"]
    # build charts config
    for bundle_id in bundle_id_tuple:
        bundle = bundles.get(bundle_id, None)
        if bundle is None:
            continue
        versions = sorted(bundle["versions"].items(), key=lambda t: (-1 * t[1], t[0]), reverse=True)
        config = {
            "type": "doughnut",
            "data": {
                "labels": [v[0] for v in versions],
                "datasets": [
                    make_dataset([v[1] for v in versions])
                ]
            }
        }
        yield bundle_id, bundle["name"], config


def osx_app_count():
    query = """
    select a.bundle_name as name, a.bundle_version_str as version_str,
    s.id as source_id, s.module as source_module, foo.count
    from (
    select ai.app_id, cms.source_id, count(*) as count
    from inventory_osxappinstance as ai
    join inventory_machinesnapshot_osx_app_instances as msai on (msai.osxappinstance_id = ai.id)
    join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msai.machinesnapshot_id)
    group by ai.app_id, cms.source_id
    ) as foo
    join inventory_osxapp as a on (foo.app_id = a.id)
    join inventory_source as s on (foo.source_id = s.id)
    """
    cursor = connection.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    for row in cursor.fetchall():
        d = dict(zip(columns, row))
        d['source'] = '{}#{}'.format(d.pop('source_module'), d.pop('source_id'))
        for k, v in d.items():
            if k != 'count' and not v:
                d[k] = '_'
        yield d


def os_version_count():
    query = """
    select o.name, o.major, o.minor, o.patch, o.build, s.id as source_id, s.module as source_module,
    count(*) as count
    from inventory_osversion as o
    join inventory_machinesnapshot as ms on (ms.os_version_id = o.id)
    join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)
    join inventory_source as s on (cms.source_id = s.id)
    group by o.name, o.major, o.minor, o.patch, o.build, s.id, s.module
    """
    cursor = connection.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    for row in cursor.fetchall():
        d = dict(zip(columns, row))
        d['source'] = '{}#{}'.format(d.pop('source_module'), d.pop('source_id'))
        for k, v in d.items():
            if k != 'count' and not v:
                d[k] = '_'
        yield d


def get_prometheus_inventory_metrics():
    registry = CollectorRegistry()
    g = Gauge('zentral_inventory_osx_apps', 'Zentral inventory OSX apps',
              ['name', 'version_str', 'source'],
              registry=registry)
    for r in osx_app_count():
        count = r.pop('count')
        g.labels(**r).set(count)
    g = Gauge('zentral_inventory_os_versions', 'Zentral inventory OS Versions',
              ['name', 'major', 'minor', 'patch', 'build', 'source'],
              registry=registry)
    for r in os_version_count():
        count = r.pop('count')
        g.labels(**r).set(count)
    return generate_latest(registry)


def inventory_events_from_machine_snapshot_commit(machine_snapshot_commit):
    source = machine_snapshot_commit.source.serialize()
    diff = machine_snapshot_commit.update_diff()
    if diff is None:
        yield ('inventory_machine_added',
               None,
               {'source': source,
                'machine_snapshot': machine_snapshot_commit.machine_snapshot.serialize()})
        yield ('inventory_heartbeat',
               machine_snapshot_commit.last_seen,
               {'source': source})
        return
    for m2m_attr, event_type in (('links', 'inventory_link_update'),
                                 ('network_interfaces', 'inventory_network_interface_update'),
                                 ('osx_app_instances', 'inventory_osx_app_instance_update'),
                                 ('deb_packages', 'inventory_deb_package_update'),
                                 ('groups', 'inventory_group_update')):
        m2m_diff = diff.get(m2m_attr, {})
        for action in ['added', 'removed']:
            for obj in m2m_diff.get(action, []):
                obj['action'] = action
                if 'source' not in obj:
                    obj['source'] = source
                yield (event_type, None, obj)
    for fk_attr in ('reference',
                    'machine',
                    'business_unit',
                    'os_version',
                    'system_info',
                    'teamviewer',
                    'puppet_node'):
        event_type = 'inventory_{}_update'.format(fk_attr)
        fk_diff = diff.get(fk_attr, {})
        for action in ['added', 'removed']:
            obj = fk_diff.get(action, None)
            if obj:
                if isinstance(obj, dict):
                    event = obj
                    if 'source' not in obj:
                        event['source'] = source
                else:
                    event = {'source': source,
                             fk_attr: obj}
                event['action'] = action
                yield (event_type, None, event)
    added_last_seen = diff.get("last_seen", {}).get("added")
    if added_last_seen:
        yield ("inventory_heartbeat",
               added_last_seen,
               {'source': source})


def commit_machine_snapshot_and_trigger_events(tree):
    try:
        machine_snapshot_commit, machine_snapshot = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    except Exception:
        logger.exception("Could not commit machine snapshot")
        log_data(tree, "/tmp", "snapshot_errors")
    else:
        if machine_snapshot_commit:
            post_inventory_events(machine_snapshot_commit.serial_number,
                                  inventory_events_from_machine_snapshot_commit(machine_snapshot_commit))
        return machine_snapshot


def verify_enrollment_secret(model, secret,
                             user_agent, public_ip_address,
                             serial_number=None, udid=None,
                             meta_business_unit=None,
                             **kwargs):
    try:
        request = EnrollmentSecret.objects.verify(model, secret,
                                                  user_agent, public_ip_address,
                                                  serial_number, udid,
                                                  meta_business_unit,
                                                  **kwargs)
    except EnrollmentSecretVerificationFailed as e:
        post_enrollment_secret_verification_failure(model,
                                                    user_agent, public_ip_address, serial_number,
                                                    e.err_msg, e.enrollment_secret)
        raise
    else:
        post_enrollment_secret_verification_success(request, model)
        return request
