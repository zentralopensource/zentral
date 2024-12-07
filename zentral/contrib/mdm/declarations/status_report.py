import logging
from zentral.contrib.mdm.models import TargetArtifact
from .utils import artifact_version_pk_from_server_token, parse_artifact_identifier


__all__ = ["get_status_report_target_artifacts_info"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.status_report")


def get_target_artifact_info(item):
    server_token = item["server-token"]
    artifact_version_pk = artifact_version_pk_from_server_token(server_token)
    if item["active"] and item["valid"] == "valid":
        status = TargetArtifact.Status.INSTALLED
    elif item["valid"] == "valid":
        status = TargetArtifact.Status.UNINSTALLED
    else:
        status = TargetArtifact.Status.FAILED
    extra_info = {"active": item["active"],
                  "valid": item["valid"]}
    reasons = item.get("reasons")
    if reasons:
        extra_info["reasons"] = reasons
    return artifact_version_pk, (status, extra_info, server_token)


def get_status_report_target_artifacts_info(status_report):
    try:
        declarations = status_report["StatusItems"]["management"]["declarations"]
    except KeyError:
        logger.error("Status report without declarations section")
        return
    target_artifacts_info = {}
    for section in ("activations", "assets", "configurations", "management"):
        for item in declarations.get(section, []):
            try:
                parse_artifact_identifier(item["identifier"])
            except ValueError:
                pass
            else:
                artifact_version_pk, info = get_target_artifact_info(item)
                target_artifacts_info[artifact_version_pk] = info
    return target_artifacts_info
