import logging
from zentral.contrib.mdm.models import Artifact, Declaration
from zentral.contrib.mdm.payloads import substitute_variables
from .exceptions import DeclarationError
from .linkers import declaration_linkers
from .utils import artifact_pk_from_identifier_and_model, get_artifact_identifier, get_artifact_version_server_token


__all__ = ["build_declaration"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.declaration")


# https://github.com/apple/device-management/blob/release/declarative/declarations/declarationbase.yaml
def build_declaration(enrollment_session, target, declaration_identifier):
    # artifact version
    try:
        artifact_pk = artifact_pk_from_identifier_and_model(declaration_identifier, Declaration)
    except ValueError:
        raise DeclarationError("Invalid Declaration Identifier")
    declaration_artifact_version = declaration_artifact = None
    for artifact, artifact_version in target.all_installed_or_to_install_serialized(
        included_types=tuple(
            t for t in Artifact.Type if t.is_raw_declaration
        ),
        done_types=tuple(
            t for t in Artifact.Type if t.is_declaration
        )
    ):
        if artifact["pk"] == artifact_pk:
            declaration_artifact = artifact
            declaration_artifact_version = artifact_version
            break
    if not declaration_artifact_version:
        raise DeclarationError(f'Could not find Declaration artifact {artifact_pk}')
    try:
        declaration = (Declaration.objects.prefetch_related("declarationref_set__artifact")
                                          .get(artifact_version__pk=declaration_artifact_version["pk"]))
    except Declaration.DoesNotExist:
        raise DeclarationError(f'Declaration for artifact version {declaration_artifact_version["pk"]} does not exist')
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
        "Identifier": get_artifact_identifier(declaration_artifact),
        "ServerToken": get_artifact_version_server_token(target, declaration_artifact, declaration_artifact_version),
        "Payload": payload,
    }
