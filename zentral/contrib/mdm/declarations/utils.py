from datetime import datetime, timedelta
import logging
import uuid
from django.contrib.contenttypes.models import ContentType
from django.core import signing
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, DataAsset, Declaration, EnrolledUser, Profile
from zentral.utils.payloads import get_payload_identifier


__all__ = [
    "artifact_pk_from_identifier_and_model",
    "artifact_version_pk_from_server_token",
    "dump_artifact_version_token",
    "get_artifact_identifier",
    "get_artifact_version_server_token",
    "get_blueprint_declaration_identifier",
    "load_artifact_version_token",
]


logger = logging.getLogger("zentral.contrib.mdm.declarations.utils")


MAX_DECLARATION_RETRIES = 3


# declaration identifiers


def artifact_path_for_type(artifact_type):
    artifact_type = Artifact.Type(artifact_type)  # TODO: necessary?
    if artifact_type == Artifact.Type.PROFILE:
        return "legacy-profile"
    elif artifact_type == Artifact.Type.DATA_ASSET:
        return "data-asset"
    elif artifact_type.is_declaration:
        return "declaration"
    else:
        raise ValueError("Artifact is not a declaration")


def artifact_model_for_path(path):
    if path == "legacy-profile":
        return Profile
    elif path == "data-asset":
        return DataAsset
    elif path == "declaration":
        return Declaration
    else:
        raise ValueError("Unknown artifact identifier path")


def get_artifact_identifier(artifact):
    path = artifact_path_for_type(artifact["type"])
    return get_payload_identifier(path, artifact["pk"])


def parse_artifact_identifier(identifier):
    prefix = get_payload_identifier() + "."
    try:
        path, artifact_pk = identifier.removeprefix(prefix).split(".")
        uuid.UUID(artifact_pk)
    except ValueError:
        raise ValueError("Invalid artifact identifier")
    model = artifact_model_for_path(path)
    return model, artifact_pk


def artifact_pk_from_identifier_and_model(identifier, model):
    parsed_model, artifact_pk = parse_artifact_identifier(identifier)
    if model == parsed_model:
        return artifact_pk
    raise ValueError("Invalid artifact identifier model")


def get_artifact_version_server_token(target, artifact, artifact_version, retry_count):
    elements = [artifact_version["pk"]]
    # reinstall on OS updates
    reinstall_on_os_update = Artifact.ReinstallOnOSUpdate(artifact["reinstall_on_os_update"])
    if reinstall_on_os_update != Artifact.ReinstallOnOSUpdate.NO:
        slice_length = None
        if reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MAJOR:
            slice_length = 1
        elif reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.MINOR:
            slice_length = 2
        elif reinstall_on_os_update == Artifact.ReinstallOnOSUpdate.PATCH:
            slice_length = 3
        if slice_length:
            elements.append("ov-{}".format(".".join(str(i) for i in target.comparable_os_version[:slice_length])))
    # reinstall interval
    reinstall_interval = artifact["reinstall_interval"]
    if reinstall_interval:
        install_num = int((datetime.utcnow() - target.target.created_at) / timedelta(seconds=reinstall_interval))
        elements.append(f"ri-{install_num}")
    # retry count
    if retry_count:
        elements.append(f"rc-{retry_count}")
    return ".".join(elements)


def artifact_version_pk_from_server_token(server_token):
    return server_token.split(".")[0]


def get_blueprint_declaration_identifier(blueprint, *suffixes):
    return get_payload_identifier("blueprint", blueprint.pk, *suffixes)


# declaration payloads download authentication


def dump_artifact_version_token(enrollment_session, target, artifact_version_pk, salt):
    if not isinstance(artifact_version_pk, str):
        artifact_version_pk = str(artifact_version_pk)
    payload = {"avpk": artifact_version_pk,
               "esm": enrollment_session._meta.model_name,
               "espk": enrollment_session.pk}
    if target.enrolled_user:
        payload["eupk"] = target.enrolled_user.pk
    return signing.dumps(payload, salt=salt)


def load_artifact_version_token(token, artifact_type, salt):
    payload = signing.loads(token, salt=salt)
    # data asset
    artifact_version = ArtifactVersion.objects.select_related("profile").get(
        pk=payload["avpk"],
        artifact__type=artifact_type,
    )
    # enrollment session
    es_ct = ContentType.objects.get_by_natural_key("mdm", payload["esm"])
    enrollment_session = (es_ct.model_class()
                               .objects
                               .select_related("enrolled_device", "realm_user")
                               .get(pk=payload["espk"]))
    # enrolled user
    try:
        enrolled_user = EnrolledUser.objects.get(pk=payload["eupk"])
    except KeyError:
        enrolled_user = None
    return artifact_version, enrollment_session, enrolled_user
