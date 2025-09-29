import logging
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.mdm.models import Artifact, Profile
from .exceptions import DeclarationError
from .utils import (artifact_pk_from_identifier_and_model,
                    dump_artifact_version_token,
                    get_artifact_identifier,
                    get_artifact_version_server_token,
                    load_artifact_version_token)


__all__ = ["dump_legacy_profile_token", "load_legacy_profile_token", "build_legacy_profile"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.legacy_profile")


TOKEN_SALT = "zentral_mdm_legacy_profile"


def dump_legacy_profile_token(enrollment_session, target, artifact_version_pk):
    return dump_artifact_version_token(enrollment_session, target, artifact_version_pk, TOKEN_SALT)


def load_legacy_profile_token(token):
    artifact_version, enrollment_session, enrolled_user = load_artifact_version_token(
        token, Artifact.Type.PROFILE, TOKEN_SALT
    )
    return artifact_version.profile, enrollment_session, enrolled_user


# https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/legacy.yaml
def build_legacy_profile(enrollment_session, target, declaration_identifier):
    try:
        artifact_pk = artifact_pk_from_identifier_and_model(declaration_identifier, Profile)
    except ValueError:
        raise DeclarationError('Invalid Profile Identifier')
    p_artifact, p_artifact_version, p_retry_count = (None, None, 0)
    for artifact, artifact_version, retry_count in target.all_installed_or_to_install_serialized(
        (Artifact.Type.PROFILE,)
    ):
        if artifact["pk"] == artifact_pk:
            p_artifact = artifact
            p_artifact_version = artifact_version
            p_retry_count = retry_count
            break
    if not p_artifact_version:
        raise DeclarationError(f'Could not find Profile artifact {artifact_pk}')
    return {
        "Type": "com.apple.configuration.legacy",
        "Identifier": get_artifact_identifier(p_artifact),
        "ServerToken": get_artifact_version_server_token(target, p_artifact, p_artifact_version, p_retry_count),
        "Payload": {
            "ProfileURL": "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm_public:profile_download_view",
                        args=(dump_legacy_profile_token(enrollment_session, target, p_artifact_version["pk"]),))
            )
        },
    }
