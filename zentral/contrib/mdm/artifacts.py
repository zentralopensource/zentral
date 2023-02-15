import copy
from datetime import datetime, timedelta
from functools import cached_property, lru_cache
import hashlib
import logging
from graphlib import TopologicalSorter
from django.db import transaction
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.os_version import make_comparable_os_version
from zentral.utils.text import shard as compute_shard
from .declarations import (build_target_management_status_subscriptions,
                           get_declaration_identifier,
                           get_legacy_profile_identifier,
                           get_legacy_profile_server_token)
from .models import (Artifact, ArtifactVersion,
                     BlueprintArtifact,
                     Channel,
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
        "versions": [
            _serialize_artifact_version(av)
            for av in artifact.artifactversion_set.all().order_by("-version")
        ],
    }
    for ra in artifact.requires.all():
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
            if min_os_version and self.comparable_os_version < min_os_version:
                return False
            if max_os_version and self.comparable_os_version >= max_os_version:
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

    def _build_topological_sorter(self, included_types=None):

        def _add_artifact_to_topological_sorter(artifact, ts, seen_artifacts):
            requires = artifact["requires"]
            ts.add(artifact["pk"], *requires)
            seen_artifacts.add(artifact["pk"])
            for r_pk in requires:
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
            # type
            if included_types and Artifact.Type(artifact["type"]) not in included_types:
                continue
            # common blueprint item scoping
            if self._test_filtered_blueprint_item(artifact):
                _add_artifact_to_topological_sorter(artifact, ts, seen_artifacts)
        ts.prepare()
        return ts

    def _walk_artifact_versions(self, callback, included_types=None):
        if self.blueprint is None:
            return

        # iterate other the tree
        ts = self._build_topological_sorter(included_types)
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
                if included_types and artifact["type"] not in included_types:
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
                _prepare_os_version(target_artifact.os_version_at_install_time, (0, 0, 0))
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
        av_status, av_installed_at, av_os_version = target_artifact["versions"].get(
            artifact_version["pk"],
            (TargetArtifact.Status.UNINSTALLED, None, (0, 0, 0))
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
            if self._test_artifact_version_to_install(artifact, artifact_version):
                artifact_to_install_pks.append((artifact["pk"], artifact_version["pk"]))
                # stop if returning only the first to install, and do not mark the artifact as done,
                # even if, because we stop, it doesn't matter.
                return only_first, False
            else:
                # continue, but mark artifact as done only if present
                return False, self._serialized_target_artifacts.get(artifact["pk"], {}).get("present", False)

        self._walk_artifact_versions(all_to_install_callback, included_types)
        return artifact_to_install_pks

    def all_to_install(self, included_types=None, only_first=False):
        artifact_version_to_install_pks = self._all_to_install_pks(included_types, only_first)
        qs = ArtifactVersion.objects.select_related("artifact", "enterprise_app", "profile", "store_app")
        if artifact_version_to_install_pks:
            return qs.filter(pk__in=(t[1] for t in artifact_version_to_install_pks))
        else:
            return qs.none()

    def next_to_install(self, included_types=None):
        return self.all_to_install(included_types, only_first=True).first()

    @lru_cache
    def all_in_scope_serialized(self, included_types=None):
        artifacts_in_scope = []

        def all_in_scope_callback(artifact, artifact_version):
            artifacts_in_scope.append((artifact, artifact_version))
            return False, True

        self._walk_artifact_versions(all_in_scope_callback, included_types)
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

    def update_target_artifact(
        self,
        artifact_version,
        status,
        extra_info=None,
        allow_reinstall=False,
        unique_install_identifier=None,
    ):
        """
        Updates the status of an artifact/version for this target
        """
        model, kwargs = self.get_target_artifact_model_and_kwargs()
        defaults = {"status": status,
                    "extra_info": extra_info or {},
                    "installed_at": None,
                    "os_version_at_install_time": None,
                    "unique_install_identifier": ""}
        if status.present:
            # those 2 attributes can only be set for a successful install
            defaults["installed_at"] = datetime.utcnow()
            defaults["os_version_at_install_time"] = self.os_version
            if unique_install_identifier:
                defaults["unique_install_identifier"] = unique_install_identifier
        with transaction.atomic():
            obj, created = model.objects.select_for_update().get_or_create(
                defaults=defaults,
                artifact_version=artifact_version,
                **kwargs
            )
            if not created:
                prev_status_present = TargetArtifact.Status(obj.status).present
                uii_changed = unique_install_identifier and obj.unique_install_identifier != unique_install_identifier
                # we update the target artifact if necessary
                updated = False
                for k, v in defaults.items():
                    if getattr(obj, k) == v:
                        # nothing to do
                        continue
                    if (
                            # if new status is not present, we can override all attributes
                            not status.present
                            # if the previous status is not present, we can override all attributes
                            or not prev_status_present
                            # standard attributes can always be overriden
                            or (k not in ("installed_at", "os_version_at_install_time", "unique_install_identifier"))
                            # special attributes require more checks
                            or (
                                # explicitly allowed to override the special attibutes
                                allow_reinstall or
                                # the unique install identifier has changed
                                uii_changed
                            )
                    ):
                        setattr(obj, k, v)
                        updated = True
                if updated:
                    obj.save()
            # cleanup
            if status.present or status == TargetArtifact.Status.UNINSTALLED:
                model.objects.filter(
                    artifact_version__artifact=artifact_version.artifact,
                    **kwargs
                ).exclude(
                    artifact_version=artifact_version
                ).delete()

    def update_target_artifacts_with_status_report(self, status_report):
        try:
            configurations = status_report["StatusItems"]["management"]["declarations"]["configurations"]
        except KeyError:
            logger.warning("Could not find configurations in status report")
            return
        target_artifacts_info = {}
        for configuration in configurations:
            if "legacy-profile" not in configuration["identifier"]:
                continue
            artifact_version_pk = configuration["server-token"].split(".")[0]
            if configuration["active"] and configuration["valid"]:
                status = TargetArtifact.Status.INSTALLED
            elif configuration["valid"]:
                status = TargetArtifact.Status.UNINSTALLED
            else:
                status = TargetArtifact.Status.FAILED
            extra_info = {"active": configuration["active"],
                          "valid": configuration["valid"]}
            unique_install_identifier = configuration["server-token"]
            target_artifacts_info[artifact_version_pk] = (status, extra_info, unique_install_identifier)
        seen_artifact_pks = []
        for artifact_version in (ArtifactVersion.objects.select_related("artifact")
                                                        .filter(pk__in=target_artifacts_info.keys())):
            seen_artifact_pks.append(artifact_version.artifact.pk)
            status, extra_info, unique_install_identifier = target_artifacts_info[str(artifact_version.pk)]
            self.update_target_artifact(
                artifact_version,
                status,
                extra_info,
                unique_install_identifier=unique_install_identifier
            )
        # cleanup
        model, kwargs = self.get_target_artifact_model_and_kwargs()
        (model.objects.filter(artifact_version__artifact__type=Artifact.Type.PROFILE,
                              **kwargs)
                      .exclude(artifact_version__artifact__pk__in=seen_artifact_pks)
                      .delete())

    # declarations

    # https://developer.apple.com/documentation/devicemanagement/activationsimple
    @cached_property
    def activation(self):
        payload = {
            "StandardConfigurations": [
                get_declaration_identifier(self.blueprint, "management-status-subscriptions"),
            ]
        }
        for artifact, _ in self.all_in_scope_serialized(included_types=(Artifact.Type.PROFILE,)):
            payload["StandardConfigurations"].append(get_legacy_profile_identifier(artifact))
        payload["StandardConfigurations"].sort()
        h = hashlib.sha1()
        for sc_id in payload["StandardConfigurations"]:
            h.update(sc_id.encode("utf-8"))
        server_token = h.hexdigest()
        return {
            "Type": "com.apple.activation.simple",
            "Identifier": get_declaration_identifier(self.blueprint, "activation"),
            "ServerToken": server_token,
            "Payload": payload,
        }

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
        for artifact, artifact_version in self.all_in_scope_serialized(included_types=(Artifact.Type.PROFILE,)):
            declarations["Configurations"].append(
               {"Identifier": get_legacy_profile_identifier(artifact),
                "ServerToken": get_legacy_profile_server_token(self, artifact, artifact_version)}
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
