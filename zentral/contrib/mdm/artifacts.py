import copy
from datetime import datetime, timedelta
from functools import cached_property, lru_cache
import hashlib
from itertools import chain
import json
import logging
from graphlib import TopologicalSorter
from django.db import connection, transaction
from psycopg2 import sql
import psycopg2.extras
import uuid
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.os_version import make_comparable_os_version
from zentral.utils.text import shard as compute_shard
from .apns import send_enrolled_device_notification, send_enrolled_user_notification
from .declarations import (build_specific_software_update_enforcement,
                           build_target_management_status_subscriptions,
                           get_blueprint_declaration_identifier,
                           get_artifact_identifier,
                           get_artifact_version_server_token,
                           get_software_update_enforcement_specific_identifier,
                           get_status_report_target_artifacts_info)
from .events import post_target_artifact_update_events
from .models import (Artifact, ArtifactVersion,
                     Blueprint, BlueprintArtifact,
                     Channel,
                     DeclarationRef,
                     DeviceArtifact, DeviceCommand,
                     TargetArtifact,
                     UserArtifact, UserCommand)


logger = logging.getLogger("zentral.contrib.mdm.artifacts")


# blueprint artifacts serialization


def _prepare_os_version(os_version, default=None):
    return make_comparable_os_version(os_version) if os_version else default


def _serialize_filtered_blueprint_item(item):
    return {
        "ios": item.ios,
        "ios_min_version": _prepare_os_version(item.ios_min_version),
        "ios_max_version": _prepare_os_version(item.ios_max_version),
        "ipados": item.ipados,
        "ipados_min_version": _prepare_os_version(item.ipados_min_version),
        "ipados_max_version": _prepare_os_version(item.ipados_max_version),
        "macos": item.macos,
        "macos_min_version": _prepare_os_version(item.macos_min_version),
        "macos_max_version": _prepare_os_version(item.macos_max_version),
        "tvos": item.tvos,
        "tvos_min_version": _prepare_os_version(item.tvos_min_version),
        "tvos_max_version": _prepare_os_version(item.tvos_max_version),
        "shard_modulo": item.shard_modulo,
        "default_shard": item.default_shard,
        "excluded_tags": [t.pk for t in item.excluded_tags.all()],
        "tag_shards": {
            # because of the JSON serialization, we prefer the str form to avoid surprises
            str(itemt.tag.pk): itemt.shard
            for itemt in item.item_tags.all()
        }
    }


def _add_artifact_to_serialization(artifact, artifacts, depth):
    artifact_pk = str(artifact.pk)
    if artifact_pk in artifacts:
        return
    required_artifacts = list(artifact.requires.all())
    referenced_artifacts = []
    if artifact.get_type().is_raw_declaration:
        # TODO: optimize?
        for ref in (
            DeclarationRef.objects.select_related("artifact")
                                  .prefetch_related("artifact__artifactversion_set")
                                  .filter(declaration__artifact_version__artifact=artifact)
        ):
            if ref.artifact not in referenced_artifacts:
                referenced_artifacts.append(ref.artifact)
    artifacts[artifact_pk] = {
        "_depth": depth,
        "pk": artifact_pk,
        "name": artifact.name,
        "type": artifact.type,
        "channel": artifact.channel,
        "install_during_setup_assistant": artifact.install_during_setup_assistant,
        "auto_update": artifact.auto_update,
        "reinstall_interval": artifact.reinstall_interval,
        "reinstall_on_os_update": artifact.reinstall_on_os_update,
        "requires": [str(ra.pk) for ra in required_artifacts],
        "references": [str(ra.pk) for ra in referenced_artifacts],
        "versions": [
            _serialize_artifact_version(av)
            for av in artifact.artifactversion_set.all().order_by("-version")
        ],
    }
    # required and referenced artifacts added with extra depth
    for ra in chain(required_artifacts, referenced_artifacts):
        _add_artifact_to_serialization(ra, artifacts, depth + 1)


def _serialize_artifact_version(artifact_version):
    d = {
        "pk": str(artifact_version.pk),
        "version": artifact_version.version
    }
    d.update(_serialize_filtered_blueprint_item(artifact_version))
    return d


def update_blueprint_serialized_artifacts(blueprint, commit=True):
    artifacts = {}
    # lock the blueprint
    Blueprint.objects.select_for_update().get(pk=blueprint.pk)
    # update the blueprint
    for bpa in (BlueprintArtifact.objects.prefetch_related("item_tags__tag",
                                                           "excluded_tags",
                                                           "artifact__requires")
                                         .select_related("artifact")
                                         .filter(blueprint=blueprint)):
        artifact = bpa.artifact
        depth = 0
        _add_artifact_to_serialization(artifact, artifacts, depth)
        artifacts[str(artifact.pk)].update(_serialize_filtered_blueprint_item(bpa))
    blueprint.serialized_artifacts = artifacts
    if commit:
        blueprint.save()


# Target


class Target:
    """A class used to represent either an enrolled device or an enrolled user

    Used in the MDM views, mostly to be able to cache some of the data.
    """
    # how often will the installation of a target artifact be retried
    ARTIFACT_RETRIES = 2

    # constructors

    def __init__(self, enrolled_device, enrolled_user=None):
        self.enrolled_device = enrolled_device
        self.enrolled_user = enrolled_user
        if enrolled_user:
            self.is_device = False
            self.target = self.enrolled_user
            self.channel = Channel.USER
        else:
            self.is_device = True
            self.target = self.enrolled_device
            self.channel = Channel.DEVICE

    # properties

    @property
    def blueprint(self):
        return self.enrolled_device.blueprint

    @property
    def serial_number(self):
        return self.enrolled_device.serial_number

    @property
    def udid(self):
        return self.enrolled_device.udid

    @property
    def platform(self):
        return self.enrolled_device.platform

    @property
    def os_version(self):
        return self.enrolled_device.os_version

    @cached_property
    def comparable_os_version(self):
        return _prepare_os_version(self.os_version, (0, 0, 0))

    @cached_property
    def tag_ids(self):
        return [t.pk for t in MetaMachine(self.serial_number).tags]

    @property
    def awaiting_configuration(self):
        return self.enrolled_device.awaiting_configuration

    @property
    def declarative_management(self):
        return self.target.declarative_management

    @property
    def client_capabilities(self):
        return self.target.client_capabilities

    @property
    def blocked(self):
        return self.enrolled_device.blocked_at is not None

    @property
    def current_declarations_token(self):
        return self.target.declarations_token

    def update_last_seen(self):
        self.target.last_seen_at = datetime.utcnow()
        self.target.save()

    # blueprint filtering method

    def _test_filtered_blueprint_item(self, item):
        # platform
        platform_key = self.platform.lower()
        if not item.get(platform_key):
            return False

        # OS version
        min_os_version = item.get(f"{platform_key}_min_version")
        max_os_version = item.get(f"{platform_key}_max_version")
        if min_os_version or max_os_version:
            if min_os_version and self.comparable_os_version < tuple(min_os_version):
                return False
            if max_os_version and self.comparable_os_version >= tuple(max_os_version):
                return False

        # excluded tags
        if set(item["excluded_tags"]).intersection(self.tag_ids):
            return False

        # shards
        shard_modulo = item["shard_modulo"]
        default_shard = item["default_shard"]
        if shard_modulo == default_shard:
            return True

        shard = compute_shard(str(item["pk"]) + self.serial_number, modulo=shard_modulo)
        if shard < default_shard:
            return True

        for tag_id in self.tag_ids:
            try:
                tag_shard = item["tag_shards"][str(tag_id)]  # pk in str form because of the JSON serialization
            except KeyError:
                pass
            else:
                if shard < tag_shard:
                    return True

        return False

    def _build_topological_sorter(self):

        def _add_artifact_to_topological_sorter(artifact, ts, seen_artifacts):
            requires = artifact["requires"]
            references = artifact.get("references", [])
            ts.add(artifact["pk"], *requires, *references)
            seen_artifacts.add(artifact["pk"])
            for r_pk in chain(requires, references):
                if r_pk not in seen_artifacts:
                    r_artifact = self.blueprint.serialized_artifacts[r_pk]
                    _add_artifact_to_topological_sorter(r_artifact, ts, seen_artifacts)

        # prepare the dependency tree
        ts = TopologicalSorter()
        seen_artifacts = set()
        for artifact in self.blueprint.serialized_artifacts.values():
            # depth
            if artifact["_depth"] != 0:
                continue
            # channel
            if Channel(artifact["channel"]) != self.channel:
                continue
            # awaiting configuration
            if self.awaiting_configuration and not artifact["install_during_setup_assistant"]:
                continue
            # common blueprint item scoping
            if self._test_filtered_blueprint_item(artifact):
                _add_artifact_to_topological_sorter(artifact, ts, seen_artifacts)

        ts.prepare()
        return ts

    def _walk_artifact_versions(self, callback):
        if self.blueprint is None:
            return

        # iterate other the tree
        ts = self._build_topological_sorter()
        iterate = True
        while iterate:
            artifact_pks = ts.get_ready()
            if not artifact_pks:
                break
            for artifact_pk in artifact_pks:
                artifact = self.blueprint.serialized_artifacts[artifact_pk]
                if Channel(artifact["channel"]) != self.channel:
                    # should never happen
                    continue
                # we have an artifact in scope
                stop, done = False, False
                for artifact_version in artifact["versions"]:
                    if self._test_filtered_blueprint_item(artifact_version):
                        # the artifact version is in scope, call the callback
                        stop, done = callback(artifact, artifact_version)
                        break
                else:
                    logger.error("No artifact version candidate found for artifact %s, enrolled device %s",
                                 artifact["pk"], self.serial_number)
                if stop:
                    iterate = False
                    break
                if done:
                    ts.done(artifact_pk)

    @cached_property
    def _serialized_target_artifacts(self):
        target_artifacts = {}
        for target_artifact in self.target.target_artifacts.select_related("artifact_version__artifact"):
            artifact = target_artifact.artifact_version.artifact
            current_artifact = target_artifacts.setdefault(
                str(artifact.pk),
                {"versions": {},
                 "type": artifact.get_type(),
                 "can_be_removed": artifact.can_be_removed,
                 "present": False,
                 "present_artifact_version_pk": None}
            )
            artifact_version_pk = str(target_artifact.artifact_version.pk)
            target_artifact_status = TargetArtifact.Status(target_artifact.status)
            current_artifact["versions"][artifact_version_pk] = (
                target_artifact_status,
                target_artifact.installed_at,
                _prepare_os_version(target_artifact.os_version_at_install_time, (0, 0, 0)),
                target_artifact.retry_count,
            )
            if target_artifact_status.present:
                current_artifact["present"] = True
                current_artifact["present_artifact_version_pk"] = artifact_version_pk
        return target_artifacts

    def _test_artifact_version_to_install(self, artifact, artifact_version):
        try:
            target_artifact = self._serialized_target_artifacts[artifact["pk"]]
        except KeyError:
            # artifact never seen → install, not present
            return True
        # get artifact version status for the target, with a sane default value
        av_status, av_installed_at, av_os_version, av_retry_count = target_artifact["versions"].get(
            artifact_version["pk"],
            (TargetArtifact.Status.UNINSTALLED, None, (0, 0, 0), 0)
        )
        if av_status.present:
            # reinstall on OS update
            reinstall_on_os_update = Artifact.ReinstallOnOSUpdate(artifact["reinstall_on_os_update"])
            if reinstall_on_os_update != Artifact.ReinstallOnOSUpdate.NO:
                if reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MAJOR:
                    slice_length = 1
                elif reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MINOR:
                    slice_length = 2
                else:
                    slice_length = 3
                if self.comparable_os_version[:slice_length] > av_os_version[:slice_length]:
                    # install because the artifact is configured to be reinstalled on OS updates
                    return True
            # reinstall interval
            reinstall_interval = artifact["reinstall_interval"]
            if (
                reinstall_interval and (
                    av_installed_at is None  # should never happen
                    or (datetime.utcnow() > av_installed_at + timedelta(days=reinstall_interval))
                )
            ):
                return True
        elif (
            av_status == TargetArtifact.Status.UNINSTALLED
            and (
                not target_artifact["present"]
                or artifact["auto_update"]
            )
        ):
            # install because artifact not present (any version) or version not present and auto update
            return True

        # all other cases, do not install
        return False

    def _all_to_install_pks(self, included_types=None, only_first=False):
        artifact_to_install_pks = []

        def all_to_install_callback(artifact, artifact_version):
            nonlocal only_first
            if (
                (not included_types or artifact["type"] in included_types)
                and self._test_artifact_version_to_install(artifact, artifact_version)
            ):
                artifact_to_install_pks.append((artifact["pk"], artifact_version["pk"]))
                # stop if returning only the first to install, and do not mark the artifact as done
                return only_first, False
            else:
                # continue, but mark artifact as done only if present
                return False, self._serialized_target_artifacts.get(artifact["pk"], {}).get("present", False)

        self._walk_artifact_versions(all_to_install_callback)
        return artifact_to_install_pks

    def all_to_install(self, included_types=None, only_first=False):
        artifact_version_to_install_pks = self._all_to_install_pks(included_types, only_first)
        qs = ArtifactVersion.objects.select_related(
            "artifact", "declaration", "enterprise_app", "profile", "store_app"
        )
        if artifact_version_to_install_pks:
            return qs.filter(pk__in=(t[1] for t in artifact_version_to_install_pks))
        else:
            return qs.none()

    def next_to_install(self, included_types=None):
        return self.all_to_install(included_types, only_first=True).first()

    @lru_cache
    def all_installed_or_to_install_serialized(self, included_types, done_types=None):
        artifacts = []
        if done_types is None:
            done_types = tuple()

        def all_installed_or_to_install_callback(artifact, artifact_version):
            target_artifact = self._serialized_target_artifacts.get(artifact["pk"], {})
            if artifact["type"] not in included_types:
                return (
                    False,
                    # if not the type, mark as done if present
                    target_artifact.get("present", False)
                    # or type in done_types
                    or artifact["type"] in done_types
                )
            else:
                _, _, _, retry_count = target_artifact.get("versions", {}).get(
                    artifact_version["pk"],
                    (None, None, None, 0)
                )
                artifacts.append((artifact, artifact_version, retry_count))
                return False, True

        self._walk_artifact_versions(all_installed_or_to_install_callback)
        return artifacts

    def all_in_scope_serialized(self):
        artifacts_in_scope = []

        def all_in_scope_callback(artifact, artifact_version):
            artifacts_in_scope.append((artifact, artifact_version))
            return False, True

        self._walk_artifact_versions(all_in_scope_callback)
        return artifacts_in_scope

    def next_to_remove(self, included_types=None):
        target_artifacts = copy.deepcopy(self._serialized_target_artifacts)
        for artifact, _ in self.all_in_scope_serialized():
            target_artifacts.pop(artifact["pk"], None)

        for target_artifact in target_artifacts.values():
            if not target_artifact["can_be_removed"]:
                continue
            if included_types and target_artifact["type"] not in included_types:
                continue
            artifact_version_pk = target_artifact["present_artifact_version_pk"]
            if artifact_version_pk:
                return ArtifactVersion.objects.select_related(
                    "artifact", "enterprise_app", "profile", "store_app"
                ).get(pk=artifact_version_pk)

    def get_db_command_model_and_kwargs(self):
        if self.is_device:
            return DeviceCommand, {"enrolled_device": self.enrolled_device}
        else:
            return UserCommand, {"enrolled_user": self.enrolled_user}

    def get_target_artifact_model_and_kwargs(self):
        if self.is_device:
            return DeviceArtifact, {"enrolled_device": self.target}
        else:
            return UserArtifact, {"enrolled_user": self.target}

    def update_target_artifacts(self, target_artifacts_info, artifact_types=None):
        """
        Update the target artifacts given a list of target artifacts info.

        If artifact_types is not None, it is a list of Artifact Types for which the target artifacts info
        is considered to be exhaustive. In that case, the target artifacts not mentionned in the list and
        of the given types are removed.
        """
        target_updated = False
        model, _ = self.get_target_artifact_model_and_kwargs()
        if not target_artifacts_info:
            if artifact_types:
                # The list is empty and considered exhaustive, we remove all the target artifacts of the given types.
                query = sql.SQL(
                    "with to_be_deleted as ("
                    "  select 'deleted' _op, ta.*, a.id a_pk, a.type a_type, a.name a_name, av.version av_version"
                    "  from {table_name} ta"
                    "  join mdm_artifactversion av on (av.id = ta.artifact_version_id)"
                    "  join mdm_artifact a on (a.id = av.artifact_id)"
                    "  where"
                    "  ta.{target_column_name} = %(target_pk)s"
                    "  and a.type in %(artifact_types)s"
                    "),  deleted as ("
                    "  delete from {table_name} where id in (select id from to_be_deleted)"
                    ") select * from to_be_deleted"
                )
            else:
                # NOOP
                return target_updated
        else:
            cleanup_condition = ''
            if artifact_types:
                # The list is considered exhaustive for these types.
                # The target artifacts of the given types for artifacts not present in the list are removed.
                cleanup_condition = (
                    'or ('
                    '  a.type in %(artifact_types)s'
                    '  and not exists ('
                    '    select * from target_artifact_info tai'
                    '    where tai.a_pk = a.id'
                    '  )'
                    ')'
                )
            # IMPORTANT: this query won't be processed by psycopg2 if the number of values is 0
            query = sql.SQL(
                "with target_artifact_info("
                "  a_pk, av_pk, present, status, extra_info, unique_install_identifier"
                ") as ("
                "  values %%s"
                "), upserted as ("
                "  insert into {table_name}"
                '  ({target_column_name}, "artifact_version_id", "status", "extra_info",'
                '   "installed_at", "os_version_at_install_time",'
                '   "unique_install_identifier", "install_count", "retry_count", "max_retry_count",'
                '   "created_at", "updated_at")'
                '  select %(target_pk)s, tai.av_pk, tai.status, tai.extra_info::jsonb,'
                # if present, insert installed at timestamp
                "  case when tai.present then %(now)s else null end,"
                # if present, insert current os version
                "  case when tai.present then %(os_version)s else null end,"
                # if present, insert unique install identifier
                "  case when tai.present then tai.unique_install_identifier else '' end,"
                # if present, set install count
                "  case when tai.present then 1 else 0 end,"
                # if not present and not uninstalled and not awaiting confirmation, bump retry count
                "  case when tai.present or tai.status in ('Uninstalled', 'AwaitingConfirmation') then 0 else 1 end,"
                # set max retry count to the default value at insert
                "  %(artifact_retries)s,"
                '  %(now)s, %(now)s'
                '  from target_artifact_info tai'
                #  conflict
                '  on conflict ({target_column_name}, "artifact_version_id") do update'
                # always update status and extra info
                '  set status = excluded.status, extra_info = excluded.extra_info,'
                # update installed_at only if the uiid changed
                '  installed_at = case when'
                '  excluded.unique_install_identifier != {table_name}.unique_install_identifier'
                '  then excluded.installed_at else {table_name}.installed_at end,'
                # update os_version_at_install_time if the uiid changed
                '  os_version_at_install_time = case when'
                '  excluded.unique_install_identifier != {table_name}.unique_install_identifier'
                '  then excluded.os_version_at_install_time else {table_name}.os_version_at_install_time end,'
                # always update the uiid
                '  unique_install_identifier = excluded.unique_install_identifier,'
                # increment install_count only if the new one changed and the uiid changed
                '  install_count = case when'
                '  excluded.unique_install_identifier != {table_name}.unique_install_identifier '
                '  then excluded.install_count + {table_name}.install_count else {table_name}.install_count end,'
                # increment retry count if the new one changed
                '  retry_count = least(excluded.retry_count + {table_name}.retry_count, {table_name}.max_retry_count),'
                # increment max retry count if new one without retry count bump, for the next install
                '  max_retry_count = case when'
                '  excluded.retry_count = 0'
                '  then {table_name}.retry_count + %(artifact_retries)s else {table_name}.max_retry_count end,'
                '  updated_at = %(now)s'
                '  where ('
                # condition of the conflict
                '    excluded.status != {table_name}.status'
                '    or excluded.extra_info != {table_name}.extra_info'
                '    or excluded.unique_install_identifier != {table_name}.unique_install_identifier'
                '    or {table_name}.status in %(absent_statuses)s'
                '    or excluded.status in %(absent_statuses)s'
                '  ) returning *'
                '), to_delete_enriched as ('
                "  select 'deleted' _op, ta.*, a.id a_pk, a.type a_type, a.name a_name, av.version av_version"
                '  from {table_name} ta'
                '  join mdm_artifactversion av on (av.id = ta.artifact_version_id)'
                '  join mdm_artifact a on (a.id = av.artifact_id)'
                '  where ta.{target_column_name} = %(target_pk)s '
                '  and not exists ('
                '    select * from target_artifact_info tai'
                '    where tai.av_pk = ta.artifact_version_id'
                '  ) and ('
                '     exists ('
                #  there is a version of the artifact that is now present or uninstalled
                '       select * from target_artifact_info tai'
                '       where tai.a_pk = a.id'
                "       and (tai.present or tai.status = 'Uninstalled')"
                f'    ) {cleanup_condition}'  # cleanup only when the list is exhaustive for some types
                '  )'
                '), do_delete as ('
                '  delete from {table_name}'
                '  where id in (select id from to_delete_enriched)'
                '  returning *'
                "), upserted_enriched as ("
                "  select case when u.created_at = %(now)s then 'created' else 'updated' end _op,"
                "  u.*, a.id a_pk, a.type a_type, a.name a_name, av.version av_version"
                "  from upserted u"
                '  join mdm_artifactversion av on (av.id = u.artifact_version_id)'
                '  join mdm_artifact a on (a.id = av.artifact_id)'
                ") select * from upserted_enriched"
                "  union"
                "  select * from to_delete_enriched"
            )
        query = query.format(
            # substitute the SQL identifiers
            table_name=sql.Identifier(model._meta.db_table),
            target_column_name=sql.Identifier("enrolled_device_id" if model == DeviceArtifact else "enrolled_user_id")
        )

        event_payloads = []

        def queue_event_payload(result_d):
            extra_info = result_d["extra_info"]
            payload = {
                "result": result_d["_op"],
                "channel": str(self.channel),
                "target_artifact": {
                    "artifact_version": {
                        "pk": str(result_d["artifact_version_id"]),
                        "version": result_d["av_version"],
                        "artifact": {
                            "pk": str(result_d["a_pk"]),
                            "type": result_d["a_type"],
                            "name": result_d["a_name"],
                        },
                    },
                    "status": result_d["status"],
                    "extra_info": json.loads(extra_info) if extra_info else None,
                    "installed_at": result_d["installed_at"],
                    "os_version_at_install_time": result_d["os_version_at_install_time"],
                    "unique_install_identifier": result_d["unique_install_identifier"],
                    "install_count": result_d["install_count"],
                    "retry_count": result_d["retry_count"],
                    "max_retry_count": result_d["max_retry_count"],
                    "created_at": result_d["created_at"],
                    "updated_at": result_d["updated_at"],
                }
            }
            if self.enrolled_user:
                payload["enrolled_user"] = {
                    "pk": self.enrolled_user.pk,
                    "user_id": self.enrolled_user.user_id,
                }
            event_payloads.append(payload)

        with transaction.atomic():
            with connection.cursor() as cursor:
                # substitute the common arguments
                query = cursor.mogrify(
                    query,
                    {"target_pk": self.target.pk,
                     "os_version": self.os_version,
                     "absent_statuses": tuple(s.value for s in TargetArtifact.Status if not s.present),
                     "artifact_retries": self.ARTIFACT_RETRIES,
                     "artifact_types": artifact_types,
                     "now": datetime.utcnow()},
                )
                if target_artifacts_info:
                    results = psycopg2.extras.execute_values(
                        cursor, query,
                        ((uuid.UUID(a_pk) if not isinstance(a_pk, uuid.UUID) else a_pk,
                          uuid.UUID(av_pk) if not isinstance(av_pk, uuid.UUID) else av_pk,
                          status.present, status,
                          psycopg2.extras.Json(extra_info), str(unique_install_identifier))
                         for a_pk, av_pk, status, extra_info, unique_install_identifier
                         in target_artifacts_info),
                        fetch=True
                    )
                else:
                    cursor.execute(query)
                    results = cursor.fetchall()
                if results:
                    target_updated = True
                    columns = [c.name for c in cursor.description]
                    for t in results:
                        queue_event_payload(dict(zip(columns, t)))

        if event_payloads:
            transaction.on_commit(lambda: post_target_artifact_update_events(self, event_payloads))

        return target_updated

    def update_target_artifacts_with_status_report(self, status_report):
        target_artifacts_info = get_status_report_target_artifacts_info(status_report)
        if target_artifacts_info is None:
            return False
        return self.update_target_artifacts(
            target_artifacts_info,
            # list exhaustive for all declarations
            tuple(t for t in Artifact.Type if t.is_declaration),
        )

    def update_target_artifact(
        self,
        artifact_version,
        status,
        extra_info=None,
        unique_install_identifier=None,
    ):
        target_artifacts_info = [
            (artifact_version.artifact.pk, artifact_version.pk,
             status, extra_info or {}, unique_install_identifier or "")
        ]
        return self.update_target_artifacts(target_artifacts_info)

    # declarations

    def supports_software_update_enforcement_specific(self):
        if not self.is_device:
            return False

        if not self.blueprint:
            return False

        client_capabilities = self.enrolled_device.client_capabilities
        if not isinstance(client_capabilities, dict):
            return
        supported_configurations = client_capabilities.get(
            "supported-payloads", {}
        ).get(
            "declarations", {}
        ).get(
            "configurations", []
        )
        if "com.apple.configuration.softwareupdate.enforcement.specific" not in supported_configurations:
            return False

        return True

    @cached_property
    def software_update_enforcement(self):
        if not self.supports_software_update_enforcement_specific():
            return

        matching_tag_count = 0
        selected_sue = None
        for sue in (self.blueprint.software_update_enforcements
                                  .filter(platforms__contains=[self.platform])
                                  .prefetch_related("tags")
                                  .order_by("pk")):
            sue_tag_ids = set(t.pk for t in sue.tags.all())
            common_tag_count = len(sue_tag_ids.intersection(self.tag_ids))
            if common_tag_count > matching_tag_count or (not sue_tag_ids and not selected_sue):
                matching_tag_count = common_tag_count
                selected_sue = sue
            elif sue_tag_ids and common_tag_count == matching_tag_count:
                logger.warning("Machine %s: software update enforcement conflict", self.serial_number)

        return selected_sue

    def iter_configuration_artifacts(self):
        """Iterate over the configuration artifacts to include in the managed activation"""
        yield from self.all_installed_or_to_install_serialized(
            included_types=tuple(
                t for t in Artifact.Type
                if t.is_configuration and t.can_be_linked_to_blueprint
            ),
            done_types=tuple(
                t for t in Artifact.Type
                if t.is_asset
            )
        )

    # https://developer.apple.com/documentation/devicemanagement/activationsimple
    @cached_property
    def activation(self):
        payload = {
            "StandardConfigurations": [
                get_blueprint_declaration_identifier(self.blueprint, "management-status-subscriptions"),
            ]
        }
        if self.software_update_enforcement:
            payload["StandardConfigurations"].append(get_software_update_enforcement_specific_identifier(self))
        for artifact, _, _ in self.iter_configuration_artifacts():
            payload["StandardConfigurations"].append(get_artifact_identifier(artifact))
        payload["StandardConfigurations"].sort()
        h = hashlib.sha1()
        for sc_id in payload["StandardConfigurations"]:
            h.update(sc_id.encode("utf-8"))
        server_token = h.hexdigest()
        return {
            "Type": "com.apple.activation.simple",
            "Identifier": get_blueprint_declaration_identifier(self.blueprint, "activation"),
            "ServerToken": server_token,
            "Payload": payload,
        }

    def iter_declaration_artifacts(self):
        """Iterate over the declaration artifacts"""
        yield from self.all_installed_or_to_install_serialized(tuple(t for t in Artifact.Type if t.is_declaration))

    # https://developer.apple.com/documentation/devicemanagement/declarationitemsresponse/manifestdeclarationitems
    @cached_property
    def declaration_items(self):
        management_status_subscriptions = build_target_management_status_subscriptions(self)
        declarations = {
            "Activations": [
                {"Identifier": self.activation["Identifier"],
                 "ServerToken": self.activation["ServerToken"]},
            ],
            "Assets": [],
            "Configurations": [
                {"Identifier": management_status_subscriptions["Identifier"],
                 "ServerToken": management_status_subscriptions["ServerToken"]}
            ],
            "Management": []
        }
        software_update_enforcement_specific = build_specific_software_update_enforcement(self, missing_ok=True)
        if software_update_enforcement_specific:
            declarations["Configurations"].append(
                {"Identifier": software_update_enforcement_specific["Identifier"],
                 "ServerToken": software_update_enforcement_specific["ServerToken"]}
            )
        for artifact, artifact_version, retry_count in self.iter_declaration_artifacts():
            artifact_type = Artifact.Type(artifact["type"])  # TODO: necessary?
            if artifact_type.is_activation:
                key = "Activations"
            elif artifact_type.is_asset:
                key = "Assets"
            elif artifact_type.is_configuration:
                key = "Configurations"
            else:
                logger.error("Unknown artifact type: %s", artifact_type)
                continue

            declarations[key].append(
               {"Identifier": get_artifact_identifier(artifact),
                "ServerToken": get_artifact_version_server_token(self, artifact, artifact_version, retry_count)}
            )
        h = hashlib.sha1()
        for key in sorted(declarations.keys()):
            for item in sorted(declarations[key], key=lambda d: (d["Identifier"], d["ServerToken"])):
                h.update(key.encode("utf-8"))
                h.update(item["Identifier"].encode("utf-8"))
                h.update(item["ServerToken"].encode("utf-8"))
        return {
            "Declarations": declarations,
            "DeclarationsToken": h.hexdigest()
        }

    # https://developer.apple.com/documentation/devicemanagement/synchronizationtokens
    @cached_property
    def sync_tokens(self):
        declarations_token = self.declaration_items["DeclarationsToken"]
        tokens_response = {
            "SyncTokens": {
                "Timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "DeclarationsToken": declarations_token
            }
        }
        return tokens_response, declarations_token

    def update_declarations_token(self, declarations_token):
        target_updated = False
        if not self.target.declarative_management:
            self.target.declarative_management = True
            target_updated = True
        if self.target.declarations_token != declarations_token:
            self.target.declarations_token = declarations_token
            target_updated = True
        if target_updated:
            self.target.save()

    # status report updates

    def update_os_info_with_status_report(self, status_report):
        target_updated = False
        if not self.is_device:
            return target_updated
        try:
            operating_system = status_report["StatusItems"]["device"]["operating-system"]
        except KeyError:
            logger.warning("Enrolled device %s: Missing operating system info in status report", self.udid)
            return target_updated
        supplemental = operating_system.get("supplemental", {})
        os_version = operating_system.get("version")
        if os_version and self.target.os_version != os_version:
            self.target.os_version = os_version
            target_updated = True
        os_version_extra = supplemental.get("extra-version", "")
        if os_version and self.target.os_version_extra != os_version_extra:
            self.target.os_version_extra = os_version_extra
            target_updated = True
        build_version = operating_system.get("build-version")
        if build_version and self.target.build_version != build_version:
            self.target.build_version = build_version
            target_updated = True
        build_version_extra = supplemental.get("build-version", "")
        if build_version and self.target.build_version_extra != build_version_extra:
            self.target.build_version_extra = build_version_extra
            target_updated = True
        return target_updated

    def update_client_capabilities_with_status_report(self, status_report):
        target_updated = False
        try:
            client_capabilities = status_report["StatusItems"]["management"]["client-capabilities"]
        except KeyError:
            logger.warning("Enrolled device %s: Could not find client capabilities in status report", self.udid)
        else:
            if client_capabilities != self.client_capabilities:
                self.target.client_capabilities = client_capabilities
                target_updated = True
        return target_updated

    def update_target_with_status_report(self, status_report):
        target_updated = self.update_os_info_with_status_report(status_report)
        target_updated |= self.update_client_capabilities_with_status_report(status_report)
        if target_updated:
            self.target.save()
        target_updated |= self.update_target_artifacts_with_status_report(status_report)
        if target_updated:
            func = send_enrolled_device_notification if self.is_device else send_enrolled_user_notification
            transaction.on_commit(lambda: func(self.target))
