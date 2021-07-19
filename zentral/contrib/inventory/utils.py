from collections import OrderedDict
import csv
from datetime import datetime
import ipaddress
from itertools import chain
import json
import logging
import os
import re
import tempfile
import urllib.parse
import zipfile
from django import forms
from django.core.files.storage import default_storage
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, transaction
from django.http import QueryDict
from django.urls import reverse
from django.utils.text import slugify
from prometheus_client import CollectorRegistry, Gauge
import xlsxwriter
from zentral.core.incidents.models import OPEN_STATUSES, SEVERITY_CHOICES
from zentral.utils.json import save_dead_letter
from .events import (post_enrollment_secret_verification_failure, post_enrollment_secret_verification_success,
                     post_inventory_events)
from .exceptions import EnrollmentSecretVerificationFailed
from .models import EnrollmentSecret, MachineSnapshotCommit, MetaMachine

logger = logging.getLogger("zentral.contrib.inventory.utils")


class BaseMSFilter:
    none_value = "\u2400"
    unknown_value = "UNKNOWN"
    title = "Untitled"
    optional = False
    free_input = False
    query_kwarg = None
    many = False
    non_grouping_expression = None
    expression = None
    grouping_set = None

    def __init__(self, idx, query_dict, hidden_value=None):
        self.idx = idx
        self.query_dict = query_dict
        if hidden_value:
            self.value = hidden_value
            self.hidden = True
        else:
            self.value = query_dict.get(self.get_query_kwarg())
            self.hidden = False
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

    def serialize(self):
        return self.get_query_kwarg()

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
        return str(grouping_value) if grouping_value else self.none_value

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
            if query_kwarg_value is None:
                query_kwarg_value = self.none_value
            else:
                query_kwarg_value = str(query_kwarg_value)
            query_kwarg = self.get_query_kwarg()
            if query_dict.get(query_kwarg) == query_kwarg_value:
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

    def process_fetched_record(self, record, for_filtering):
        return


class SourceFilter(BaseMSFilter):
    title = "Sources"
    query_kwarg = "src"
    expression = ("jsonb_build_object("
                  "'id', src.id, 'module', src.module, "
                  "'name', src.name, 'config', src.config) as src_j")
    grouping_set = ("src.id", "src_j")

    def joins(self):
        yield "join inventory_source as src on (ms.source_id = src.id)"

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "src.id = %s"
            else:
                yield "src.id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    @staticmethod
    def display_name(source):
        # TODO: better. see also zentral.inventory.models
        dn = [source["name"]]
        config = source.get("config")
        if config:
            host = config.get("host")
            if host:
                dn.append(host)
        return "/".join(e for e in dn if e)

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return self.none_value
        else:
            return self.display_name(grouping_value)

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if not grouping_value:
            return None
        else:
            return grouping_value["id"]

    def process_fetched_record(self, record, for_filtering):
        source = record.pop("src_j", None)
        if source and source["id"]:
            source["display_name"] = self.display_name(source)
            record["source"] = source
            if for_filtering:
                source.pop("config", None)
        elif for_filtering:
            record["source"] = {"display_name": self.unknown_value.title(),
                                "name": self.unknown_value}


class OSVersionFilter(BaseMSFilter):
    title = "OS"
    optional = True
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
            if self.value != self.none_value:
                yield "osv.id = %s"
            else:
                yield "osv.id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    @staticmethod
    def version(os_version):
        return ".".join(str(num) for num in
                        (os_version.get(attr) for attr in ("major", "minor", "patch"))
                        if num is not None)

    def version_with_build(self, os_version):
        version = self.version(os_version)
        build = os_version.get("build")
        if build:
            version = "{} ({})".format(version, build)
        return version.strip()

    def display_name(self, os_version):
        return " ".join(e for e in (os_version["name"], self.version_with_build(os_version)) if e)

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return self.none_value
        else:
            return self.display_name(grouping_value)

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record, for_filtering):
        os_version = record.pop("osv_j", None)
        if os_version and os_version["id"]:
            os_version["version"] = self.version(os_version)
            os_version["display_name"] = self.display_name(os_version)
            record["os_version"] = os_version
        elif for_filtering:
            record["os_version"] = {"version": self.unknown_value,
                                    "display_name": self.unknown_value.title()}


class MetaBusinessUnitFilter(BaseMSFilter):
    title = "Meta business units"
    optional = True
    query_kwarg = "mbu"
    expression = "jsonb_build_object('id', mbu.id, 'name', mbu.name) as mbu_j"
    grouping_set = ("mbu.id", "mbu_j")

    def joins(self):
        return ["left join inventory_businessunit as bu on (ms.business_unit_id = bu.id)",
                "left join inventory_metabusinessunit as mbu on (bu.meta_business_unit_id = mbu.id)"]

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "mbu.id = %s"
            else:
                yield "mbu.id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return self.none_value
        else:
            return grouping_value["name"] or "?"

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record, for_filtering):
        meta_business_unit = record.pop("mbu_j", None)
        if meta_business_unit and meta_business_unit["id"]:
            record["meta_business_unit"] = meta_business_unit
        elif for_filtering:
            record["meta_business_unit"] = {"name": self.unknown_value}


class MachineGroupFilter(BaseMSFilter):
    title = "Groups"
    optional = True
    many = True
    query_kwarg = "g"
    expression = "jsonb_build_object('id', mg.id, 'name', mg.name) as mg_j"
    grouping_set = ("mg.id", "mg_j")

    def joins(self):
        return ["left join inventory_machinesnapshot_groups as msg on (ms.id = msg.machinesnapshot_id)",
                "left join inventory_machinegroup as mg on (mg.id = msg.machinegroup_id)"]

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "mg.id = %s"
            else:
                yield "mg.id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return self.none_value
        else:
            return grouping_value["name"] or "?"

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record, for_filtering):
        machine_groups = []
        for machine_group in record.pop("mg_j", []):
            if not machine_group["id"]:
                continue
            if machine_group not in machine_groups:
                machine_groups.append(machine_group)
        record["machine_groups"] = machine_groups


class TagFilter(BaseMSFilter):
    title = "Tags"
    optional = True
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
            if self.value != self.none_value:
                yield "t.id = %s"
            else:
                yield "t.id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
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
            return self.none_value
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

    def process_fetched_record(self, record, for_filtering):
        tags = []
        for tag in record.pop("tag_j", []):
            if not tag["id"]:
                continue
            display_name = tag["name"]
            if not tag["meta_business_unit"]["id"]:
                tag["meta_business_unit"] = None
            else:
                display_name = "/".join(s for s in (tag["meta_business_unit"]["name"], display_name) if s)
            if for_filtering:
                tag = display_name
            else:
                tag["display_name"] = display_name
            if tag not in tags:
                tags.append(tag)
        record["tags"] = tags


class OSXAppInstanceFilter(BaseMSFilter):
    title = "macOS app instances"
    optional = True
    many = True
    query_kwarg = "mosai"

    def joins(self):
        yield "left join inventory_machinesnapshot_osx_app_instances as mosai on (mosai.machinesnapshot_id = ms.id)"

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "mosai.osxappinstance_id = %s"
            else:
                yield "mosai.osxappinstance_id is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value


class BundleFilter(BaseMSFilter):
    optional = True
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
            if self.value != self.none_value:
                yield "a{}.id = %s".format(self.idx)
            else:
                yield "a{}.id is null".format(self.idx)

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def serialize(self):
        if self.bundle_name:
            return "a.n.{}".format(self.bundle_name)
        elif self.bundle_id:
            return "a.i.{}".format(self.bundle_id)

    @staticmethod
    def display_name(osx_app):
        return " ".join(e for e in (osx_app["bundle_name"], osx_app["bundle_version_str"]) if e)

    def label_for_grouping_value(self, grouping_value):
        if not grouping_value:
            return self.none_value
        if self.bundle_id:
            # TODO hack. Try to set a better title.
            bundle_name = grouping_value["bundle_name"]
            if bundle_name:
                self.title = bundle_name
        return self.display_name(grouping_value)

    def grouping_value_from_grouping_result(self, grouping_result):
        gv = super().grouping_value_from_grouping_result(grouping_result)
        if gv["id"] is None:
            return None
        return gv

    def query_kwarg_value_from_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value["id"]

    def process_fetched_record(self, record, for_filtering):
        osx_apps = []
        for osx_app in record.pop(self.grouping_set[-1], []):
            if not osx_app["id"]:
                continue
            osx_app["display_name"] = self.display_name(osx_app)
            if osx_app not in osx_apps:
                osx_apps.append(osx_app)
        osx_apps.sort(key=lambda app: (app.get("bundle_version"), app.get("bundle_version_str"), app.get("id")))
        if not for_filtering:
            # TODO: verify no conflict
            record.setdefault("osx_apps", OrderedDict())[self.title] = osx_apps
        else:
            bundles_dict = record.setdefault("bundles", {})
            bundle_idx = len(bundles_dict)  # we do not use self.idx because we want to start from 0
            bundle_dict = bundles_dict.setdefault(str(bundle_idx), {})
            if self.bundle_name:
                bundle_dict["name"] = self.bundle_name
            elif self.bundle_id:
                bundle_dict["id"] = self.bundle_id
            if not osx_apps:
                bundle_dict["version"] = {"min": self.unknown_value, "max": self.unknown_value}
            else:
                bundle_dict["version"] = {"min": (osx_apps[0].get("bundle_version_str")
                                                  or osx_apps[0].get("bundle_version")),
                                          "max": (osx_apps[-1].get("bundle_version_str")
                                                  or osx_apps[-1].get("bundle_version"))}


class TypeFilter(BaseMSFilter):
    title = "Types"
    optional = True
    query_kwarg = "tp"
    expression = "ms.type"
    grouping_set = ("ms.type",)

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "ms.type = %s"
            else:
                yield "ms.type is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def label_for_grouping_value(self, grouping_value):
        if grouping_value:
            return grouping_value.title()
        else:
            return self.none_value

    def process_fetched_record(self, record, for_filtering):
        if for_filtering and record.get("type") is None:
            record["type"] = self.unknown_value


class PlaformFilter(BaseMSFilter):
    title = "Platforms"
    optional = True
    query_kwarg = "pf"
    expression = "ms.platform"
    grouping_set = ("ms.platform",)

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "ms.platform = %s"
            else:
                yield "ms.platform is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def process_fetched_record(self, record, for_filtering):
        if for_filtering and record.get("platform") is None:
            record["platform"] = self.unknown_value


class SerialNumberFilter(BaseMSFilter):
    query_kwarg = "sn"
    free_input = True
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

    def process_fetched_record(self, record, for_filtering):
        if not for_filtering:
            record["urlsafe_serial_number"] = MetaMachine.make_urlsafe_serial_number(record["serial_number"])


class ComputerNameFilter(BaseMSFilter):
    query_kwarg = "cn"
    free_input = True
    non_grouping_expression = "si.computer_name"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.value:
            self.value = self.value.strip()

    def joins(self):
        yield "left join inventory_systeminfo as si on (ms.system_info_id = si.id)"

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "si.id is not null and si.computer_name ~* %s"
            else:
                yield "si.id is null or si.computer_name is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def process_fetched_record(self, record, for_filtering):
        computer_name = record.pop("computer_name", None)
        if computer_name:
            record.setdefault("system_info", {})["computer_name"] = computer_name
        elif for_filtering:
            record.setdefault("system_info", {})["computer_name"] = self.unknown_value


class PrincipalUserNameFilter(BaseMSFilter):
    query_kwarg = "pu"
    free_input = True
    non_grouping_expression = "pu.principal_name, pu.display_name"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.value:
            self.value = self.value.strip()

    def joins(self):
        yield "left join inventory_principaluser as pu on (ms.principal_user_id = pu.id)"

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "pu.id is not null and (pu.principal_name ~* %s or pu.display_name ~* %s)"
            else:
                yield "pu.id is null or pu.principal_name is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value
            yield self.value

    def process_fetched_record(self, record, for_filtering):
        for attr in ("principal_name", "display_name"):
            val = record.pop(attr, None)
            if val:
                record.setdefault("principal_user", {})[attr] = val


class HardwareModelFilter(BaseMSFilter):
    title = "Hardware models"
    optional = True
    query_kwarg = "hm"
    expression = "si.hardware_model"
    grouping_set = ("si.hardware_model",)

    def joins(self):
        yield "left join inventory_systeminfo as si on (ms.system_info_id = si.id)"

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "si.hardware_model = %s"
            else:
                yield "si.hardware_model is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def process_fetched_record(self, record, for_filtering):
        hardware_model = record.pop("hardware_model", None)
        if hardware_model:
            record.setdefault("system_info", {})["hardware_model"] = hardware_model
        elif for_filtering:
            record.setdefault("system_info", {})["hardware_model"] = self.unknown_value


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


class IncidentSeverityFilter(BaseMSFilter):
    title = "Incidents severities"
    optional = True
    query_kwarg = "mis"
    expression = "mis.max_incident_severity as max_incident_severity"
    grouping_set = ("mis.max_incident_severity",)
    severities_dict = dict(SEVERITY_CHOICES)

    def joins(self):
        yield (
            "left join ("
            "select mi.serial_number as serial_number, max(i.severity) as max_incident_severity "
            "from incidents_machineincident as mi "
            "join incidents_incident as i on (i.id = mi.incident_id) "
            "where i.status in ({}) "
            "group by mi.serial_number"
            ") as mis on (mis.serial_number = ms.serial_number)"
        ).format(",".join("'{}'".format(s) for s in OPEN_STATUSES))

    def wheres(self):
        if self.value:
            if self.value != self.none_value:
                yield "mis.max_incident_severity = %s"
            else:
                yield "mis.max_incident_severity is null"

    def where_args(self):
        if self.value and self.value != self.none_value:
            yield self.value

    def label_for_grouping_value(self, grouping_value):
        if grouping_value is None:
            return self.none_value
        else:
            return self.severities_dict.get(grouping_value, str(grouping_value))

    def process_fetched_record(self, record, for_filtering):
        max_incident_severity = record.pop("max_incident_severity", None)
        if max_incident_severity is not None:
            record["max_incident_severity"] = {"value": max_incident_severity,
                                               "keyword": str(self.severities_dict.get(max_incident_severity,
                                                                                       max_incident_severity))}
        elif for_filtering:
            record["max_incident_severity"] = {"value": 0,
                                               "keyword": "No incidents"}


class MSQuery:
    paginate_by = 50
    itersize = 1000
    default_filters = [
        DateTimeFilter,
        SourceFilter,
        MetaBusinessUnitFilter,
        TagFilter,
        IncidentSeverityFilter,
        TypeFilter,
        PlaformFilter,
        HardwareModelFilter,
        OSVersionFilter,
        SerialNumberFilter,
        ComputerNameFilter,
        PrincipalUserNameFilter,
    ]

    def __init__(self, query_dict=None):
        self.query_dict = query_dict or {}
        try:
            self.page = int(self.query_dict.get("page", 1))
        except ValueError:
            self.page = 1
        self.filters = []
        self._redirect = False
        self._deserialize_filters(self.query_dict.get("sf"))
        self._grouping_results = None
        self._count = None
        self._grouping_links = None

    # filters configuration

    def add_filter(self, filter_class, **filter_kwargs):
        """add a filter"""
        self.filters.append(filter_class(len(self.filters), self.query_dict, **filter_kwargs))

    def force_filter(self, filter_class, **filter_kwargs):
        """replace an existing filter from the same class or add it"""
        found_f = None
        for idx, f in enumerate(self.filters):
            if isinstance(f, filter_class):
                found_f = f
                break
        if not found_f:
            self.add_filter(filter_class, **filter_kwargs)
        else:
            new_f = filter_class(found_f.idx, self.query_dict, **filter_kwargs)
            self.filters = [f if f.idx != found_f.idx else new_f for f in self.filters]

    def _deserialize_filters(self, serialized_filters):
        try:
            serialized_filters = serialized_filters.split("-")
            default = False
        except Exception:
            serialized_filters = []
            default = True
            self._redirect = True
        for filter_class in self.default_filters:
            if default or not filter_class.optional or filter_class.query_kwarg in serialized_filters:
                self.add_filter(filter_class)
        for serialized_filter in serialized_filters:
            if serialized_filter.startswith("a."):
                attr, value = re.sub(r"^a\.", "", serialized_filter).split(".", 1)
                if attr == "n":
                    self.add_filter(BundleFilter, bundle_name=value)
                elif attr == "i":
                    self.add_filter(BundleFilter, bundle_id=value)

    def serialize_filters(self, filter_to_add=None, filter_to_remove=None, include_hidden=False):
        return "-".join(f.serialize() for f in chain(self.filters, [filter_to_add])
                        if f and f.optional and not f == filter_to_remove and (include_hidden or not f.hidden))

    def get_url(self, page=None):
        qd = self.query_dict.copy()
        qd["sf"] = self.serialize_filters()
        if page is not None:
            qd["page"] = page
        return "?{}".format(urllib.parse.urlencode(qd))

    def redirect_url(self):
        if self._redirect:
            # bad filters
            return self.get_url()
        elif self.count() < (self.page - 1) * self.paginate_by:
            # out of the page range. redirect to first page.
            return self.get_url(page=1)
        elif (
            self.count() == 1 and
            any(isinstance(f.value, str) and f.value > "" for f in self.filters if f.free_input)
        ):
            # redirect to machine
            for serial_number, machine_snapshots in self.fetch():
                for machine_snapshot in machine_snapshots:
                    return reverse("inventory:machine", args=(machine_snapshot["urlsafe_serial_number"],))

    def get_canonical_query_dict(self):
        # used to serialize the state of the msquery object
        # even with forced hidden filter values
        # see inventory export
        qd = QueryDict(mutable=True)
        qd["sf"] = self.serialize_filters(include_hidden=True)
        for f in self.filters:
            if f.value is not None:
                qd[f.serialize()] = f.value
        return qd

    def get_urlencoded_canonical_query_dict(self):
        return self.get_canonical_query_dict().urlencode()

    def available_filters(self):
        links = []
        idx = len(self.filters)
        for filter_class in self.default_filters:
            for f in self.filters:
                if isinstance(f, filter_class):
                    break
            else:
                available_filter = filter_class(idx, self.query_dict)
                available_filter_qd = self.query_dict.copy()
                available_filter_qd["sf"] = self.serialize_filters(filter_to_add=available_filter)
                links.append((available_filter.title,
                              "?{}".format(urllib.parse.urlencode(available_filter_qd))))
                idx += 1
        return links

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
            if f.hidden:
                continue
            f_choices = f.grouping_choices_from_grouping_results(grouping_results)
            if f_choices:
                yield f, f_choices

    def grouping_links(self):
        if self._grouping_links is None:
            self._grouping_links = []
            count = self.count()
            for f, f_choices in self.grouping_choices():
                f_links = []
                f_up_links = []
                for label, f_count, down_query_dict, up_query_dict in f_choices:
                    if up_query_dict is not None:
                        up_link = "?{}".format(urllib.parse.urlencode(up_query_dict))
                        f_up_links.append(up_link)
                        down_link = None
                    else:
                        up_link = None
                        down_link = "?{}".format(urllib.parse.urlencode(down_query_dict))
                    if count > 0:
                        f_perc = f_count * 100 / count
                    else:
                        f_perc = 0
                    f_links.append((label, f_count, f_perc, down_link, up_link))
                f_links.sort(key=lambda t: (t[0] == f.none_value, (t[0] or "").upper()))
                if f.optional:
                    remove_filter_query_dict = self.query_dict.copy()
                    remove_filter_query_dict.pop("page", None)
                    remove_filter_query_dict.pop(f.get_query_kwarg(), None)
                    remove_filter_query_dict["sf"] = self.serialize_filters(filter_to_remove=f)
                    f_r_link = "?{}".format(urllib.parse.urlencode(remove_filter_query_dict))
                else:
                    f_r_link = None
                f_up_link = None
                if len(f_up_links) == 1:
                    f_up_link = f_up_links[0]
                elif len(f_up_links) > 1:
                    # should not happen
                    logger.warning("More than one uplink for filter %s - %s", f.get_query_kwarg(), self.query_dict)
                self._grouping_links.append((f, f_links, f_r_link, f_up_link))
        return self._grouping_links

    # fetching

    def _build_fetching_query_with_args(self, paginate=True):
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
        # pagination
        if paginate:
            limit = max(self.paginate_by, 1)
            args.append(limit)
            offset = max((self.page - 1) * limit, 0)
            args.append(offset)
            limit_offset = " limit %s offset %s"
        else:
            limit_offset = ""
        meta_query = (
            "select ms.serial_number, json_agg(row_to_json(ms.*)) as machine_snapshots "
            "from ({}) ms "
            "group by ms.serial_number "
            "order by min(ms.computer_name) asc, ms.serial_number asc{}"
        ).format(query, limit_offset)
        return meta_query, args

    def _make_fetching_query(self, paginate=True):
        query, args = self._build_fetching_query_with_args(paginate)
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        for rows in iter(lambda: cursor.fetchmany(self.itersize), connection.features.empty_fetchmany_value):
            for row in rows:
                yield dict(zip(columns, row))

    def fetch(self, paginate=True, for_filtering=False):
        for record in self._make_fetching_query(paginate):
            for machine_snapshot in record["machine_snapshots"]:
                for f in self.filters:
                    f.process_fetched_record(machine_snapshot, for_filtering)
            yield record["serial_number"], record["machine_snapshots"]

    # export
    def export_sheets_data(self):
        title = "Machines"
        headers = [
            "Source ID", "Source",
            "SN",
            "Meta Business Unit ID",
            "Meta Business Unit Name",
            "Type", "Platform",
            "Name",
            "Hardware model",
            "OS",
            "Principal user principal name",
            "Principal user display name",
            "tags"
        ]
        row_idx = 0
        rows = []
        include_max_incident_severity = False
        for serial_number, machine_snapshots in self.fetch(paginate=False):
            for machine_snapshot in machine_snapshots:
                if row_idx == 0:
                    if "max_incident_severity" in machine_snapshot:
                        include_max_incident_severity = True
                        headers.extend(["Max incident severity", "Max incident severity display"])
                    for app_title in machine_snapshot.get("osx_apps", {}):
                        for suffix in ("min", "max"):
                            headers.append("{} {}".format(app_title, suffix))
                row_idx += 1
                system_info = machine_snapshot.get("system_info", {})
                meta_business_unit = machine_snapshot.get("meta_business_unit", {})
                row = [
                    machine_snapshot["source"]["id"],
                    machine_snapshot["source"].get("display_name") or "",
                    serial_number,
                    meta_business_unit.get("id") or "",
                    meta_business_unit.get("name") or "",
                    machine_snapshot.get("type") or "",
                    machine_snapshot.get("platform") or "",
                    system_info.get("computer_name") or "",
                    system_info.get("hardware_model") or ""
                ]
                os_version = machine_snapshot.get("os_version")
                if os_version:
                    os_version_dn = os_version.get("display_name") or ""
                else:
                    os_version_dn = ""
                row.append(os_version_dn)
                principal_user = machine_snapshot.get("principal_user")
                if principal_user:
                    pu_pn = principal_user.get("principal_name") or ""
                    pu_dn = principal_user.get("display_name") or ""
                else:
                    pu_pn = pu_dn = ""
                row.extend([pu_pn, pu_dn])
                row.append(
                    "|".join(dn for dn in (t.get("display_name") for t in machine_snapshot.get("tags", [])) if dn)
                )
                if include_max_incident_severity:
                    mis = machine_snapshot.get("max_incident_severity", {})
                    row.extend([mis.get("value") or "",
                                mis.get("keyword") or ""])
                for _, app_versions in machine_snapshot.get("osx_apps", {}).items():
                    if app_versions:
                        min_app_version = app_versions[0]["display_name"]
                        max_app_version = app_versions[-1]["display_name"]
                    else:
                        min_app_version = max_app_version = ""
                    row.extend([min_app_version, max_app_version])
                rows.append(row)
        yield title, headers, rows

        # aggregations
        for f, f_links, _, _ in self.grouping_links():
            rows = []
            for label, f_count, f_perc, _, _ in f_links:
                if label == "\u2400":
                    label = "NULL"
                elif not isinstance(label, str):
                    label = str(label)
                rows.append([label, f_count, f_perc])
            yield f.title, ["Value", "Count", "%"], rows

    def export_xlsx(self, f_obj):
        workbook = xlsxwriter.Workbook(f_obj)
        # machines
        for title, headers, rows in self.export_sheets_data():
            ws = workbook.add_worksheet(title)
            row_idx = col_idx = 0
            for header in headers:
                ws.write_string(row_idx, col_idx, header)
                col_idx += 1
            for row in rows:
                row_idx += 1
                col_idx = 0
                for value in row:
                    if isinstance(value, (int, float)):
                        ws.write_number(row_idx, col_idx, value)
                    else:
                        if not isinstance(value, str):
                            value = str(value)
                        ws.write_string(row_idx, col_idx, value)
                    col_idx += 1
        workbook.close()

    def export_zip(self, f_obj):
        with zipfile.ZipFile(f_obj, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_f:
            for title, headers, rows in self.export_sheets_data():
                tmp_file_fh, tmp_file = tempfile.mkstemp()
                with os.fdopen(tmp_file_fh, mode='w', newline='') as csv_f:
                    w = csv.writer(csv_f)
                    w.writerow(headers)
                    for row in rows:
                        w.writerow(row)
                zip_f.write(tmp_file, "{}.csv".format(slugify(title)))
                os.unlink(tmp_file)


class BundleFilterForm(forms.Form):
    bundle_id = forms.CharField(label="Bundle id", required=False,
                                widget=forms.TextInput(attrs={"class": "form-control",
                                                              "placeholder": "Bundle id"}))
    bundle_name = forms.CharField(label="Bundle name", required=False,
                                  widget=forms.TextInput(attrs={"class": "form-control",
                                                                "placeholder": "Bundle name"}))

    def clean(self):
        cleaned_data = super().clean()
        bundle_name = cleaned_data.get("bundle_name")
        bundle_id = cleaned_data.get("bundle_id")
        if bundle_name and bundle_id:
            raise forms.ValidationError("Bundle id and bundle name cannot be both specified.")
        elif not bundle_name and not bundle_id:
            raise forms.ValidationError("Choose a bundle id or a bundle name.")


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
    return registry


def inventory_events_from_machine_snapshot_commit(machine_snapshot_commit):
    source = machine_snapshot_commit.source.serialize()
    diff = machine_snapshot_commit.update_diff()
    if diff is None:
        machine_payload = machine_snapshot_commit.machine_snapshot.serialize()
        machine_payload
        yield ('add_machine',
               None,
               machine_snapshot_commit.machine_snapshot.serialize(
                   exclude=["deb_packages",
                            "disks",
                            "network_interfaces",
                            "osx_app_instance",
                            "program_instances"]
               ))
        yield ('inventory_heartbeat',
               machine_snapshot_commit.last_seen,
               {'source': source})
        return
    for m2m_diff_attr in ('certificates',
                          'deb_packages',
                          'disks',
                          'groups',
                          'links',
                          'network_interfaces',
                          'osx_app_instances',
                          'program_instances'):
        m2m_diff = diff.get(m2m_diff_attr, {})
        if not m2m_diff:
            continue
        event_attr = m2m_diff_attr[:-1]
        for diff_action, event_action in [('added', 'add'), ('removed', 'remove')]:
            event_type = f"{event_action}_machine_{event_attr}"
            for obj in m2m_diff.get(diff_action, []):
                yield (event_type, None, {event_attr: obj, "source": source})
    for attr in ('business_unit',
                 'os_version',
                 'system_info',
                 'teamviewer',
                 'puppet_node',
                 'principal_user'):
        fk_diff = diff.get(attr, {})
        if not fk_diff:
            continue
        for diff_action, event_action in [('added', 'add'), ('removed', 'remove')]:
            event_type = f"{event_action}_machine_{attr}"
            obj = fk_diff.get(diff_action)
            if obj:
                if not isinstance(obj, dict):
                    # this should not happen
                    logger.error("Unsupported diff value %s %s", attr, diff_action)
                    continue
                yield (event_type, None, {attr: obj, "source": source})
    added_last_seen = diff.get("last_seen", {}).get("added")
    if added_last_seen:
        yield ("inventory_heartbeat", added_last_seen, {'source': source})


def commit_machine_snapshot_and_trigger_events(tree):
    try:
        machine_snapshot_commit, machine_snapshot = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    except Exception:
        logger.exception("Could not commit machine snapshot")
        save_dead_letter(tree, "machine snapshot commit error")
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


def clean_ip_address(addr):
    if not isinstance(addr, str):
        return None
    addr = addr.strip()
    if not addr:
        return None
    try:
        addr = ipaddress.IPv4Address(addr)
    except ValueError:
        try:
            addr = ipaddress.IPv6Address(addr)
        except ValueError:
            return None
        else:
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            else:
                return str(addr)
    else:
        return str(addr)


# App export


def _export_machine_csv_zip(query, basename, window_size=5000):
    columns = None
    csv_files = []
    current_source_name = csv_f = csv_w = csv_p = None

    # iter all rows over a server-side cursor
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(f"DECLARE machine_csv_zip_export_cursor CURSOR FOR {query}")
        while True:
            cursor.execute("FETCH %s FROM machine_csv_zip_export_cursor", [window_size])
            if columns is None:
                columns = [c.name for c in cursor.description]
            rows = cursor.fetchall()
            if not rows:
                if current_source_name:
                    csv_f.close()
                    csv_files.append((current_source_name, csv_p))
                break
            for row in rows:
                source_name = row[columns.index("source_name")]
                if source_name != current_source_name:
                    if current_source_name:
                        csv_f.close()
                        csv_files.append((current_source_name, csv_p))
                    current_source_name = source_name
                    csv_fh, csv_p = tempfile.mkstemp()
                    csv_f = os.fdopen(csv_fh, mode='w', newline='')
                    csv_w = csv.writer(csv_f)
                    csv_w.writerow(columns)
                csv_w.writerow(row)

    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_a:
        for source_name, csv_p in csv_files:
            zip_a.write(csv_p, "{}.csv".format(slugify(source_name)))
            os.unlink(csv_p)

    filename = "{}_{:%Y-%m-%d_%H-%M-%S}.zip".format(slugify(basename).replace("-", "_"), datetime.utcnow())
    filepath = os.path.join("exports", filename)
    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)
    os.unlink(zip_p)

    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Length": default_storage.size(filepath),
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    }


def export_machine_macos_app_instances():
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name,"
        "oa.bundle_id, oa.bundle_name, oa.bundle_display_name, oa.bundle_version, oa.bundle_version_str,"
        "oai.bundle_path, oai.path "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_osx_app_instances as msoai on (msoai.machinesnapshot_id = ms.id) "
        "join inventory_osxappinstance as oai on (oai.id = msoai.osxappinstance_id) "
        "join inventory_osxapp as oa on (oa.id = oai.app_id) "
        "order by s.name, cms.serial_number, oa.bundle_id, oa.bundle_name, oa.bundle_version, oa.bundle_version_str;"
    )
    return _export_machine_csv_zip(query, "inventory_machine_macos_app_instances_export")


def export_machine_program_instances():
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name,"
        "p.name, p.version, p.language, p.publisher, p.identifying_number,"
        "pi.install_location, pi.install_source, pi.uninstall_string, pi.install_date "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_program_instances as mspi on (mspi.machinesnapshot_id = ms.id) "
        "join inventory_programinstance as pi on (pi.id = mspi.programinstance_id) "
        "join inventory_program as p on (p.id = pi.program_id) "
        "order by s.name, cms.serial_number, p.name, p.version, p.identifying_number, p.id;"
    )
    return _export_machine_csv_zip(query, "inventory_machine_program_instances_export")


def export_machine_deb_packages():
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name,"
        "dp.name, dp.version, dp.source, dp.size, dp.arch,"
        "dp.revision, dp.status, dp.maintainer, dp.section, dp.priority "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_deb_packages as msdp on (msdp.machinesnapshot_id = ms.id) "
        "join inventory_debpackage as dp on (dp.id = msdp.debpackage_id) "
        "order by s.name, cms.serial_number, dp.name, dp.version, dp.revision, dp.id;"
    )
    return _export_machine_csv_zip(query, "inventory_machine_deb_packages_export")


def export_machine_snapshots(source_name=None, window_size=5000):
    args = []
    query = (
        "select "
        "ms.serial_number, ms.imei, ms.meid, ms.platform, ms.type, ms.mt_created_at as last_change,"
        "max(msc.last_seen) as last_seen,"
        "json_build_object('module', s.module, 'name', s.name) as source,"
        "json_agg(json_build_object("
        "  'anchor_text', l.anchor_text,"
        "  'url', l.url"
        ")) as links,"
        "json_build_object("
        "  'name', o.name,"
        "  'major', o.major,"
        "  'minor', o.minor,"
        "  'patch', o.patch,"
        "  'build', o.build"
        ") as os_version,"
        "json_build_object("
        "  'computer_name', si.computer_name,"
        "  'hostname', si.hostname,"
        "  'hardware_model', si.hardware_model,"
        "  'hardware_serial', si.hardware_serial,"
        "  'cpu_type', si.cpu_type,"
        "  'cpu_subtype', si.cpu_subtype,"
        "  'cpu_brand', si.cpu_brand,"
        "  'cpu_physical_cores', si.cpu_physical_cores,"
        "  'cpu_logical_cores', si.cpu_logical_cores,"
        "  'physical_memory', si.physical_memory"
        ") as system_info,"
        "json_build_object("
        "  'source', json_build_object('type', pus.type, 'properties', pus.properties),"
        "  'unique_id', pu.unique_id,"
        "  'principal_name', pu.principal_name,"
        "  'display_name', pu.display_name"
        ") as principal_user,"
        "json_agg(json_build_object('name', d.name, 'size', d.size)) as disks,"
        "json_agg(json_build_object("
        "  'interface', ni.interface,"
        "  'mac', ni.mac,"
        "  'address', ni.address,"
        "  'mask', ni.mask,"
        "  'broadcast', ni.broadcast"
        ")) as network_interfaces "
        "from inventory_machinesnapshot as ms "
        "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id) "
        "join inventory_machinesnapshotcommit as msc on (msc.machine_snapshot_id = ms.id) "
        "join inventory_source as s on (ms.source_id = s.id) "
        "left join inventory_machinesnapshot_links as ml on (ml.machinesnapshot_id = ms.id) "
        "left join inventory_link as l on (ml.link_id = l.id) "
        "left join inventory_osversion as o on (ms.os_version_id = o.id) "
        "left join inventory_systeminfo as si on (ms.system_info_id = si.id) "
        "left join inventory_principaluser as pu on (ms.principal_user_id = pu.id) "
        "left join inventory_principalusersource as pus on (pu.source_id = pus.id) "
        "left join inventory_machinesnapshot_disks as md on (md.machinesnapshot_id = ms.id) "
        "left join inventory_disk as d on (d.id = md.disk_id) "
        "left join inventory_machinesnapshot_network_interfaces as mni on (mni.machinesnapshot_id = ms.id) "
        "left join inventory_networkinterface as ni on (ni.id = mni.networkinterface_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
        args.append(source_name.upper())
    query += (
        "group by "
        "ms.serial_number, ms.imei, ms.meid, ms.platform, ms.type, ms.mt_created_at,"
        "s.module, s.name,"
        "o.name, o.major, o.minor, o.patch, o.build,"
        "si.computer_name, si.hostname, si.hardware_model, si.hardware_serial,"
        "si.cpu_type, si.cpu_subtype, si.cpu_brand, si.cpu_physical_cores, si.cpu_logical_cores, si.physical_memory,"
        "pus.type, pus.properties, pu.unique_id, pu.principal_name, pu.display_name "
        "order by s.name, ms.serial_number"
    )

    columns = None
    json_files = []
    current_source_name = json_f = json_p = None

    def _prepare_machine_snapshot(row_d):
        for k, v in list(row_d.items()):
            if v is None:
                del row_d[k]
            elif isinstance(v, dict):
                _prepare_machine_snapshot(v)
                if not v:
                    del row_d[k]
            elif isinstance(v, list):
                nv = []
                for vv in v:
                    if isinstance(vv, dict):
                        _prepare_machine_snapshot(vv)
                        if not vv or vv in nv:
                            continue
                    nv.append(vv)
                if nv:
                    row_d[k] = nv
                else:
                    del row_d[k]
        return row_d

    # iter all rows over a server-side cursor
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(f"DECLARE machine_snapshot_export_cursor CURSOR FOR {query}", args)
        while True:
            cursor.execute("FETCH %s FROM machine_snapshot_export_cursor", [window_size])
            if columns is None:
                columns = [c.name for c in cursor.description]
            rows = cursor.fetchall()
            if not rows:
                if current_source_name:
                    json_f.close()
                    json_files.append((current_source_name, json_p))
                break
            for row in rows:
                row_d = dict(zip(columns, row))
                source_name = row_d["source"]["name"]
                if source_name != current_source_name:
                    if current_source_name:
                        json_f.close()
                        json_files.append((current_source_name, json_p))
                    current_source_name = source_name
                    json_fh, json_p = tempfile.mkstemp()
                    json_f = os.fdopen(json_fh, mode='w')
                json_f.write(json.dumps(_prepare_machine_snapshot(row_d), cls=DjangoJSONEncoder))
                json_f.write("\n")

    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_a:
        for source_name, json_p in json_files:
            zip_a.write(json_p, "{}.json".format(slugify(source_name)))
            os.unlink(json_p)

    filename = "machine_snapshots_{:%Y-%m-%d_%H-%M-%S}.zip".format(datetime.utcnow())
    filepath = os.path.join("exports", filename)
    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)
    os.unlink(zip_p)

    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Length": default_storage.size(filepath),
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    }
