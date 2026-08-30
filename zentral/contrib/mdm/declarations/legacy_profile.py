import logging
from django.urls import reverse
from zentral.conf import api_base_url
from zentral.contrib.mdm.models import Artifact, Profile
from .utils import (dump_artifact_version_token,
                    load_artifact_version_token,
                    resolve_declaration_artifact_version)


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
    artifact_version_pk, server_token = resolve_declaration_artifact_version(
        target, declaration_identifier, Profile, (Artifact.Type.PROFILE,)
    )
    return {
        "Type": "com.apple.configuration.legacy",
        "Identifier": declaration_identifier,
        "ServerToken": server_token,
        "Payload": {
            "ProfileURL": "{}{}".format(
                api_base_url(),
                reverse("mdm_public:profile_download_view",
                        args=(dump_legacy_profile_token(enrollment_session, target, artifact_version_pk),))
            )
        },
    }
