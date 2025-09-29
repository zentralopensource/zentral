import logging
from django.urls import reverse
from zentral.conf import settings
from zentral.contrib.mdm.cert_issuer_backends import test_acme_payload
from zentral.contrib.mdm.models import Artifact, CertAsset, Platform
from .exceptions import DeclarationError
from .utils import (artifact_pk_from_identifier_and_model,
                    dump_artifact_version_token,
                    get_artifact_identifier,
                    get_artifact_version_server_token,
                    load_artifact_version_token)


__all__ = ["build_cert_asset", "dump_cert_asset_token", "load_cert_asset_token"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.cert_asset")


TOKEN_SALT = "zentral_mdm_cert_asset"


def dump_cert_asset_token(enrollment_session, target, artifact_version_pk):
    return dump_artifact_version_token(enrollment_session, target, artifact_version_pk, TOKEN_SALT)


def load_cert_asset_token(token):
    artifact_version, enrollment_session, enrolled_user = load_artifact_version_token(
        token, Artifact.Type.CERT_ASSET, TOKEN_SALT
    )
    return artifact_version.cert_asset, enrollment_session, enrolled_user


# https://github.com/apple/device-management/blob/release/declarative/declarations/assets/credential.acme.yaml
# https://github.com/apple/device-management/blob/release/declarative/declarations/assets/credential.scep.yaml
def build_cert_asset(enrollment_session, target, declaration_identifier):
    try:
        artifact_pk = artifact_pk_from_identifier_and_model(declaration_identifier, CertAsset)
    except ValueError:
        raise DeclarationError('Invalid CertAsset Identifier')
    ca_artifact, ca_artifact_version, ca_retry_count = (None, None, 0)
    for artifact, artifact_version, retry_count in target.all_installed_or_to_install_serialized(
        (Artifact.Type.CERT_ASSET,)
    ):
        if artifact["pk"] == artifact_pk:
            ca_artifact = artifact
            ca_artifact_version = artifact_version
            ca_retry_count = retry_count
            break
    if not ca_artifact_version:
        raise DeclarationError(f'Could not find CertAsset artifact {artifact_pk}')
    try:
        cert_asset = (CertAsset.objects.select_related("acme_issuer", "scep_issuer")
                                       .get(artifact_version__pk=ca_artifact_version["pk"]))
    except CertAsset.DoesNotExist:
        raise DeclarationError(f'CertAsset for artifact version {ca_artifact_version["pk"]} does not exist')
    decl_type = url_name = None
    if cert_asset.acme_issuer:
        enrolled_device = target.enrolled_device
        acme, _, _ = test_acme_payload(
            Platform(enrolled_device.platform),
            enrolled_device.comparable_os_version,
            enrolled_device.model
        )
        if acme:
            decl_type = "com.apple.asset.credential.acme"
            url_name = "acme_credential"
    if decl_type is None and cert_asset.scep_issuer:
        decl_type = "com.apple.asset.credential.scep"
        url_name = "scep_credential"
    if decl_type is None:
        raise DeclarationError(
            f'No compatible issuers found for CertAsset {ca_artifact_version["pk"]} '
            f'and device {enrolled_device.serial_number}'
        )
    return {
        "Type": decl_type,
        "Identifier": get_artifact_identifier(ca_artifact),
        "ServerToken": get_artifact_version_server_token(target, ca_artifact, ca_artifact_version, ca_retry_count),
        "Payload": {
            "Reference": {
                "DataURL": "https://{}{}".format(
                    settings["api"]["fqdn"],
                    reverse(f"mdm_public:{url_name}",
                            args=(dump_cert_asset_token(enrollment_session, target, ca_artifact_version["pk"]),))
                ),
                "ContentType": "application/json",
            },
            "Accessible": cert_asset.accessible,
        },
    }
