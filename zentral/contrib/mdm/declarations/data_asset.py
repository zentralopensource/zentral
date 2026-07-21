import logging
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.mdm.models import Artifact, DataAsset
from .exceptions import DeclarationError
from .utils import (dump_artifact_version_token,
                    load_artifact_version_token,
                    resolve_declaration_artifact_version)


__all__ = ["build_data_asset", "dump_data_asset_token", "load_data_asset_token"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.data_asset")


TOKEN_SALT = "zentral_mdm_data_asset"


def dump_data_asset_token(enrollment_session, target, artifact_version_pk):
    return dump_artifact_version_token(enrollment_session, target, artifact_version_pk, TOKEN_SALT)


def load_data_asset_token(token):
    artifact_version, enrollment_session, enrolled_user = load_artifact_version_token(
        token, Artifact.Type.DATA_ASSET, TOKEN_SALT
    )
    return artifact_version.data_asset, enrollment_session, enrolled_user


# https://github.com/apple/device-management/blob/release/declarative/declarations/assets/data.yaml
def build_data_asset(enrollment_session, target, declaration_identifier):
    artifact_version_pk, server_token = resolve_declaration_artifact_version(
        target, declaration_identifier, DataAsset, (Artifact.Type.DATA_ASSET,)
    )
    try:
        data_asset = DataAsset.objects.get(artifact_version__pk=artifact_version_pk)
    except DataAsset.DoesNotExist:
        raise DeclarationError(f'DataAsset for artifact version {artifact_version_pk} does not exist')
    return {
        "Type": "com.apple.asset.data",
        "Identifier": declaration_identifier,
        "ServerToken": server_token,
        "Payload": {
            "Reference": {
                "DataURL": "https://{}{}".format(
                    settings["api"]["fqdn"],
                    reverse("mdm_public:data_asset_download_view",
                            args=(dump_data_asset_token(enrollment_session, target, artifact_version_pk),))
                ),
                "ContentType": data_asset.get_content_type(),
                "Size": data_asset.file_size,
                "Hash-SHA-256": data_asset.file_sha256,
            }
        },
    }
