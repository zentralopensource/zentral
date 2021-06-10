import logging
from django.http import Http404
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.payloads import get_payload_identifier
from zentral.contrib.mdm.models import Artifact, ArtifactType, ArtifactVersion


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
                {"Name": "device.model.family"},
                {"Name": "device.model.identifier"},
                {"Name": "device.model.marketing-name"},
                {"Name": "device.operating-system.build-version"},
                {"Name": "device.operating-system.family"},
                {"Name": "device.operating-system.marketing-name"},
                {"Name": "device.operating-system.version"},
                {"Name": "management.client-capabilities"},
                {"Name": "management.declarations"},
                {"Name": "management.push-token"},
            ]
        },
        "ServerToken": blueprint.updated_at.isoformat(),
        "Type": "com.apple.configuration.management.status-subscriptions"
    }


def get_legacy_profile_identifier(artifact):
    return get_payload_identifier("legacy-profiles", artifact.pk)


# https://developer.apple.com/documentation/devicemanagement/legacyprofile
def build_legacy_profile(blueprint, declaration_identifier, enrollment_session):
    artifact_pk = declaration_identifier.split(".")[-1]
    artifact_version = (ArtifactVersion.objects.select_related("artifact")
                                               .filter(artifact__pk=artifact_pk,
                                                       artifact__blueprintartifact__blueprint=blueprint)
                                               .order_by("-version")).first()
    if artifact_version is None:
        raise Http404
    return {
        "Identifier": get_legacy_profile_identifier(artifact_version.artifact),
        "Payload": {
            "ProfileURL": "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm:profile_download_view", args=(enrollment_session._meta.model_name,
                                                           enrollment_session.enrollment_secret.secret,
                                                           artifact_version.pk))
            )
        },
        "ServerToken": str(artifact_version.pk),
        "Type": "com.apple.configuration.legacy"
    }


# https://developer.apple.com/documentation/devicemanagement/activationsimple
def build_activation(blueprint):
    standard_configurations = [get_declaration_identifier(blueprint, "management-status-subscriptions")]
    for artifact in Artifact.objects.filter(type="Profile", blueprintartifact__blueprint=blueprint):
        standard_configurations.append(get_legacy_profile_identifier(artifact))
    return {
        "Identifier": get_declaration_identifier(blueprint, "activation"),
        "Payload": {
            "StandardConfigurations": standard_configurations
        },
        "ServerToken": blueprint.updated_at.isoformat(),
        "Type": "com.apple.activation.simple"
    }


# https://developer.apple.com/documentation/devicemanagement/declarationitemsresponse/manifestdeclarationitems
def build_declaration_items(blueprint):
    configurations = [
        {"Identifier": get_declaration_identifier(blueprint, "management-status-subscriptions"),
         "ServerToken": blueprint.updated_at.isoformat()},
    ]
    for artifact_version in (ArtifactVersion.objects.select_related("artifact")
                                                    .filter(artifact__type=ArtifactType.Profile.name,
                                                            artifact__blueprintartifact__blueprint=blueprint)):
        configurations.append({"Identifier": get_legacy_profile_identifier(artifact_version.artifact),
                               "ServerToken": str(artifact_version.pk)})
    return {
        "Declarations": {
            "Activations": [
                {"Identifier": get_declaration_identifier(blueprint, "activation"),
                 "ServerToken": blueprint.updated_at.isoformat()},
            ],
            "Assets": [],
            "Configurations": configurations,
            "Management": []
        },
        "DeclarationsToken": blueprint.updated_at.isoformat()
    }
