import logging
from zentral.contrib.mdm.models import Artifact, Declaration
from zentral.contrib.mdm.payloads import substitute_variables
from .exceptions import DeclarationError
from .linkers import declaration_linkers, get_declaration_info
from .utils import artifact_pk_from_identifier_and_model, get_artifact_identifier, get_artifact_version_server_token


__all__ = [
    "build_declaration",
    "verify_declaration_source",
]


logger = logging.getLogger("zentral.contrib.mdm.declarations.declaration")


# https://github.com/apple/device-management/blob/release/declarative/declarations/declarationbase.yaml
def build_declaration(enrollment_session, target, declaration_identifier):
    # artifact version
    try:
        artifact_pk = artifact_pk_from_identifier_and_model(declaration_identifier, Declaration)
    except ValueError:
        raise DeclarationError("Invalid Declaration Identifier")
    d_artifact, d_artifact_version, d_retry_count = (None, None, 0)
    for artifact, artifact_version, retry_count in target.all_installed_or_to_install_serialized(
        included_types=tuple(
            t for t in Artifact.Type if t.is_raw_declaration
        ),
        done_types=tuple(
            t for t in Artifact.Type if t.is_declaration
        )
    ):
        if artifact["pk"] == artifact_pk:
            d_artifact = artifact
            d_artifact_version = artifact_version
            d_retry_count = retry_count
            break
    if not d_artifact_version:
        raise DeclarationError(f'Could not find Declaration artifact {artifact_pk}')
    try:
        declaration = (Declaration.objects.prefetch_related("declarationref_set__artifact")
                                          .get(artifact_version__pk=d_artifact_version["pk"]))
    except Declaration.DoesNotExist:
        raise DeclarationError(f'Declaration for artifact version {d_artifact_version["pk"]} does not exist')
    # prepare payload
    payload = declaration.payload
    # substitute references to other declarations
    references = {tuple(ref.key): get_artifact_identifier({"pk": str(ref.artifact.pk), "type": ref.artifact.type})
                  for ref in declaration.declarationref_set.all()}
    if references:
        try:
            linker = declaration_linkers[declaration.type]
        except KeyError:
            raise DeclarationError(f'Unknown declaration type {declaration.type}')
        payload = linker.substitute_refs(declaration.payload, references)
    # substitute variables
    payload = substitute_variables(payload, enrollment_session, target.enrolled_user)
    return {
        "Type": declaration.type,
        "Identifier": get_artifact_identifier(d_artifact),
        "ServerToken": get_artifact_version_server_token(target, d_artifact, d_artifact_version, d_retry_count),
        "Payload": payload,
    }


# verify_declaration_source, used in the declaration forms and in the declaration serializer


def verify_declaration_source_type(declaration_type, artifact):
    artifact_type = artifact.get_type()
    if artifact_type.is_activation:
        type_prefix = "com.apple.activation."
    elif artifact_type.is_asset:
        type_prefix = "com.apple.asset."
    elif artifact_type.is_configuration:
        type_prefix = "com.apple.configuration."
    else:
        # should never happen
        raise RuntimeError("Unsupported artifact type")
    if not declaration_type.startswith(type_prefix):
        raise ValueError(f"Invalid declaration Type for {artifact_type}")
    # same type for all declarations of a given artifact
    if (
        artifact.pk
        and Declaration.objects.filter(artifact_version__artifact=artifact).exclude(type=declaration_type).exists()
    ):
        raise ValueError("A declaration with a different Type exists for this artifact")


def verify_declaration_source_identifier(identifier, artifact):
    qs = Declaration.objects.filter(identifier=identifier)
    if artifact.pk:
        qs = qs.exclude(artifact_version__artifact=artifact)
    if qs.exists():
        raise ValueError("A declaration with this Identifier already exists")
    if (
        artifact.pk
        and Declaration.objects.filter(artifact_version__artifact=artifact).exclude(identifier=identifier).exists()
    ):
        raise ValueError("A declaration with a different Identifier exists for this artifact")


def verify_declaration_source_server_token(server_token, declaration):
    qs = Declaration.objects.filter(server_token=server_token)
    if declaration:
        qs = qs.exclude(pk=declaration.pk)
    if qs.exists():
        raise ValueError("A declaration with this ServerToken already exists")


def verify_declaration_source_payload(payload, artifact):
    if artifact.pk:
        declaration = (
            Declaration.objects.filter(artifact_version__artifact=artifact)
                               .order_by("-artifact_version__version")
                               .first()
        )
        if declaration and declaration.payload == payload:
            raise ValueError("The latest declaration of this artifact has the same Payload")


def verify_declaration_source(artifact, source, declaration=None):
    info = get_declaration_info(source, artifact.get_channel(), artifact.get_platforms(), ensure_server_token=True)
    verify_declaration_source_type(info["type"], artifact)
    verify_declaration_source_identifier(info["identifier"], artifact)
    verify_declaration_source_server_token(info["server_token"], declaration)
    verify_declaration_source_payload(info["payload"], artifact)
    return info
