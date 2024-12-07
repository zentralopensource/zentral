import copy
from datetime import datetime, timedelta
from functools import cached_property, lru_cache
import hashlib
from itertools import chain
import logging
from graphlib import TopologicalSorter
from django.db import transaction
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
        qs = ArtifactVersion.objects.select_related("artifact", "enterprise_app", "profile", "store_app")
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
            if artifact["type"] not in included_types:
                return (
                    False,
                    # if not the type, mark as done if present
                    self._serialized_target_artifacts.get(artifact["pk"], {}).get("present", False)
                    # or type in done_types
                    or artifact["type"] in done_types
                )
            else:
                artifacts.append((artifact, artifact_version))
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
        target_updated = False
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
            target_updated = created
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
                    target_updated = True
                    obj.save()
            # cleanup
            if status.present or status == TargetArtifact.Status.UNINSTALLED:
                deleted_count, _ = model.objects.filter(
                    artifact_version__artifact=artifact_version.artifact,
                    **kwargs
                ).exclude(
                    artifact_version=artifact_version
                ).delete()
                target_updated |= deleted_count > 0
        return target_updated

    def update_target_artifacts_with_status_report(self, status_report):
        target_updated = False
        target_artifacts_info = get_status_report_target_artifacts_info(status_report)
        if target_artifacts_info is None:
            return target_updated
        seen_artifact_pks = []
        for artifact_version in (ArtifactVersion.objects.select_related("artifact")
                                                        .filter(pk__in=target_artifacts_info.keys())):
            seen_artifact_pks.append(artifact_version.artifact.pk)
            status, extra_info, unique_install_identifier = target_artifacts_info[str(artifact_version.pk)]
            target_updated |= self.update_target_artifact(
                artifact_version,
                status,
                extra_info,
                unique_install_identifier=unique_install_identifier
            )
        # cleanup
        model, kwargs = self.get_target_artifact_model_and_kwargs()
        deleted_count, _ = model.objects.filter(
            artifact_version__artifact__type=Artifact.Type.PROFILE,
            **kwargs
        ).exclude(
            artifact_version__artifact__pk__in=seen_artifact_pks
        ).delete()
        target_updated |= deleted_count > 0
        return target_updated

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
        for artifact, _ in self.iter_configuration_artifacts():
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
        for artifact, artifact_version in self.iter_declaration_artifacts():
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
                "ServerToken": get_artifact_version_server_token(self, artifact, artifact_version)}
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
