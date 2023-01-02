import logging
import uuid
from django.http import Http404
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.payloads import get_payload_identifier
from zentral.contrib.mdm.models import Artifact, ArtifactType, ArtifactVersion, DeviceArtifact, TargetArtifactStatus


logger = logging.getLogger("zentral.contrib.mdm.declarations")


def get_declaration_identifier(blueprint, *suffixes):
    return get_payload_identifier("blueprint", blueprint.pk, *suffixes)


# https://developer.apple.com/documentation/devicemanagement/managementstatussubscriptions
# https://developer.apple.com/documentation/devicemanagement/status_reports
def build_management_status_subscriptions(blueprint):
    return {
        "Identifier": get_declaration_identifier(blueprint, "management-status-subscriptions"),
        "Payload": {
            "StatusItems": [
                {"Name": "device.identifier.serial-number"},
                {"Name": "device.identifier.udid"},
                {"Name": "device.model.family"},
                {"Name": "device.model.identifier"},
                {"Name": "device.model.marketing-name"},
                {"Name": "device.operating-system.build-version"},
                {"Name": "device.operating-system.family"},
                {"Name": "device.operating-system.marketing-name"},
                {"Name": "device.operating-system.version"},
                {"Name": "mdm.app"},
                {"Name": "passcode.is-compliant"},
                {"Name": "passcode.is-present"},
                {"Name": "management.client-capabilities"},
                {"Name": "management.declarations"},
                {"Name": "management.push-token"},
            ]
        },
        "ServerToken": "2",  # We start with hard-coded one, because it will not change at first
        "Type": "com.apple.configuration.management.status-subscriptions"
    }


def get_legacy_profile_identifier(artifact_pk):
    return get_payload_identifier("legacy-profile", artifact_pk)


# https://developer.apple.com/documentation/devicemanagement/legacyprofile
def build_legacy_profile(blueprint, declaration_identifier):
    artifact_pk = declaration_identifier.split(".")[-1]
    artifact_version = (ArtifactVersion.objects.select_related("artifact")
                                               .filter(artifact__pk=artifact_pk,
                                                       artifact__blueprintartifact__blueprint=blueprint)
                                               .order_by("-version")).first()
    if artifact_version is None:
        raise Http404
    return {
        "Identifier": get_legacy_profile_identifier(artifact_version.artifact.pk),
        "Payload": {
            "ProfileURL": "https://{}{}".format(
                settings["api"]["fqdn_mtls"],
                reverse("mdm:profile_download_view", args=(artifact_version.pk,))
            )
        },
        "ServerToken": str(artifact_version.pk),
        "Type": "com.apple.configuration.legacy"
    }


# https://developer.apple.com/documentation/devicemanagement/activationsimple
def update_blueprint_activation(blueprint, commit=True):
    payload = {
        "StandardConfigurations": [
            get_declaration_identifier(blueprint, "management-status-subscriptions"),
        ]
    }
    for artifact in Artifact.objects.filter(type=ArtifactType.Profile.name, blueprintartifact__blueprint=blueprint):
        payload["StandardConfigurations"].append(get_legacy_profile_identifier(artifact.pk))
    payload["StandardConfigurations"].sort()
    if not blueprint.activation or blueprint.activation["Payload"] != payload:
        blueprint.activation = {
            "Identifier": get_declaration_identifier(blueprint, "activation"),
            "Payload": payload,
            "ServerToken": str(uuid.uuid4()),
            "Type": "com.apple.activation.simple"
        }
        if commit:
            blueprint.save()
        return True
    return False


# https://developer.apple.com/documentation/devicemanagement/declarationitemsresponse/manifestdeclarationitems
def update_blueprint_declaration_items(blueprint, commit=True):
    management_status_subscriptions = build_management_status_subscriptions(blueprint)
    declarations = {
        "Activations": [
            {"Identifier": blueprint.activation["Identifier"],
             "ServerToken": blueprint.activation["ServerToken"]},
        ],
        "Assets": [],
        "Configurations": [
            {"Identifier": management_status_subscriptions["Identifier"],
             "ServerToken": management_status_subscriptions["ServerToken"]}
        ],
        "Management": []
    }
    for artifact_pk, artifact_version_pk in ArtifactVersion.objects.latest_for_blueprint(blueprint,
                                                                                         ArtifactType.Profile):
        declarations["Configurations"].append(
           {"Identifier": get_legacy_profile_identifier(artifact_pk),
            "ServerToken": str(artifact_version_pk)}
        )
    declarations["Configurations"].sort(key=lambda d: (d["Identifier"], d["ServerToken"]))
    if not blueprint.declaration_items or blueprint.declaration_items["Declarations"] != declarations:
        blueprint.declaration_items = {
            "Declarations": declarations,
            "DeclarationsToken": str(uuid.uuid4())
        }
        if commit:
            blueprint.save()
        return True
    return False


def update_enrolled_device_artifacts(enrolled_device, status_report):
    try:
        configurations = status_report["StatusItems"]["management"]["declarations"]["configurations"]
    except KeyError:
        logger.warning("Could not find configurations in status report")
        return
    installed_artifacts = {}
    for configuration in configurations:
        if "legacy-profile" in configuration["identifier"]:
            artifact_pk = configuration["identifier"].split(".")[-1]
            artifact_version_pk = configuration["server-token"]
            if configuration["active"] and configuration["valid"] == "valid":
                installed_artifacts[artifact_pk] = artifact_version_pk
    # cleanup
    (DeviceArtifact.objects.filter(enrolled_device=enrolled_device,
                                   artifact_version__artifact__type=ArtifactType.Profile.name)
                           .exclude(artifact_version__artifact__pk__in=list(installed_artifacts.keys()))
                           .delete())
    for artifact_pk, artifact_version_pk in installed_artifacts.items():
        # cleanup
        (DeviceArtifact.objects.filter(enrolled_device=enrolled_device,
                                       artifact_version__artifact__pk=artifact_pk)
                               .exclude(artifact_version__pk=artifact_version_pk).delete())
        # update or create
        DeviceArtifact.objects.update_or_create(
            enrolled_device=enrolled_device,
            artifact_version=ArtifactVersion.objects.get(pk=artifact_version_pk),
            defaults={"status": TargetArtifactStatus.Installed.name}
        )
