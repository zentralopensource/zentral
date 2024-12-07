import logging
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.mdm.models import Artifact, DataAsset
from .exceptions import DeclarationError
from .utils import (artifact_pk_from_identifier_and_model,
                    dump_artifact_version_token,
                    get_artifact_identifier,
                    get_artifact_version_server_token,
                    load_artifact_version_token)


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
    try:
        artifact_pk = artifact_pk_from_identifier_and_model(declaration_identifier, DataAsset)
    except ValueError:
        raise DeclarationError('Invalid DataAsset Identifier')
    data_asset_artifact_version = data_asset_artifact = None
    for artifact, artifact_version in target.all_installed_or_to_install_serialized((Artifact.Type.DATA_ASSET,)):
        if artifact["pk"] == artifact_pk:
            data_asset_artifact = artifact
            data_asset_artifact_version = artifact_version
            break
    if not data_asset_artifact_version:
        raise DeclarationError(f'Could not find DataAsset artifact {artifact_pk}')
    try:
        data_asset = DataAsset.objects.get(artifact_version__pk=data_asset_artifact_version["pk"])
    except DataAsset.DoesNotExist:
        raise DeclarationError(f'DataAsset for artifact version {data_asset_artifact_version["pk"]} does not exist')
    return {
        "Type": "com.apple.asset.data",
        "Identifier": get_artifact_identifier(data_asset_artifact),
        "ServerToken": get_artifact_version_server_token(target, data_asset_artifact, data_asset_artifact_version),
        "Payload": {
            "Reference": {
                "DataURL": "https://{}{}".format(
                    settings["api"]["fqdn"],
                    reverse("mdm_public:data_asset_download_view",
                            args=(dump_data_asset_token(enrollment_session, target, artifact_version["pk"]),))
                ),
                "ContentType": data_asset.get_content_type(),
                "Size": data_asset.file_size,
                "Hash-SHA-256": data_asset.file_sha256,
            }
        },
    }
