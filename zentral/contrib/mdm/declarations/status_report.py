import logging
from zentral.contrib.mdm.models import TargetArtifact
from .utils import artifact_version_pk_from_server_token, parse_artifact_identifier


__all__ = [
    "SOFTWARE_UPDATE_ENFORCEMENT_DECLARATION_STATUS_ITEM",
    "get_status_report_declaration_status",
    "get_status_report_errors",
    "get_status_report_scalar_status_items",
    "get_status_report_target_artifacts_info",
]


logger = logging.getLogger("zentral.contrib.mdm.declarations.status_report")


# https://github.com/apple/device-management/tree/release/declarative/status
SCALAR_STATUS_ITEMS = frozenset((
    "softwareupdate.beta-enrollment",
    "softwareupdate.device-id",
    "softwareupdate.failure-reason",
    "softwareupdate.install-reason",
    "softwareupdate.install-state",
    "softwareupdate.pending-version",
))

# status item groups with a dedicated reader, or not consumed yet
KNOWN_STATUS_ITEM_GROUPS = frozenset((
    "device.identifier",
    "device.model",
    "device.operating-system",
    "management.client-capabilities",
    "management.declarations",
))

# not an Apple status item: the management.declarations entry of the target's own
# software update enforcement declaration, stored next to the softwareupdate.* items
SOFTWARE_UPDATE_ENFORCEMENT_DECLARATION_STATUS_ITEM = "zentral.softwareupdate.enforcement-declaration"


def _iter_scalar_status_items(node, prefix):
    for key, value in node.items():
        name = f"{prefix}.{key}" if prefix else key
        if name in SCALAR_STATUS_ITEMS:
            yield name, value
        elif name in KNOWN_STATUS_ITEM_GROUPS:
            continue
        elif isinstance(value, dict):
            yield from _iter_scalar_status_items(value, name)
        else:
            logger.debug("Unknown status item %s", name)


def get_status_report_scalar_status_items(status_report):
    status_items = status_report.get("StatusItems")
    if not isinstance(status_items, dict):
        return {}
    return dict(_iter_scalar_status_items(status_items, ""))


# https://github.com/apple/device-management/blob/release/declarative/protocol/statusreport.yaml
def get_status_report_errors(status_report):
    errors = []
    for error in status_report.get("Errors") or []:
        if not isinstance(error, dict):
            continue
        status_item = error.get("StatusItem")
        if not isinstance(status_item, str):
            continue
        reasons = error.get("Reasons")
        errors.append({"status_item": status_item,
                       "reasons": reasons if isinstance(reasons, list) else []})
    return errors


def get_status_report_declaration_status(status_report, identifier):
    try:
        declarations = status_report["StatusItems"]["management"]["declarations"]
    except (KeyError, TypeError):
        return
    for section in ("activations", "assets", "configurations", "management"):
        for item in declarations.get(section) or []:
            if isinstance(item, dict) and item.get("identifier") == identifier:
                status = {key: item.get(key) for key in ("active", "valid", "server-token")}
                reasons = item.get("reasons")
                if reasons:
                    status["reasons"] = reasons
                return status


def get_target_artifact_info(item):
    server_token = item["server-token"]
    artifact_version_pk = artifact_version_pk_from_server_token(server_token)
    if item["valid"] == "valid":
        if item["active"]:
            status = TargetArtifact.Status.INSTALLED
        else:
            status = TargetArtifact.Status.UNINSTALLED
    elif item["valid"] == "unknown":
        if item["active"]:
            status = TargetArtifact.Status.AWAITING_CONFIRMATION
        else:
            status = TargetArtifact.Status.UNINSTALLED
    else:
        status = TargetArtifact.Status.FAILED
    extra_info = {"active": item["active"],
                  "valid": item["valid"]}
    reasons = item.get("reasons")
    if reasons:
        extra_info["reasons"] = reasons
    return artifact_version_pk, status, extra_info, server_token


def get_status_report_target_artifacts_info(status_report):
    try:
        declarations = status_report["StatusItems"]["management"]["declarations"]
    except KeyError:
        logger.debug("Status report without declarations section")
        return
    # A re-pushed artifact version can be reported under two server-tokens in one report; both
    # map to one artifact_version_pk, which the target-artifact upsert can't accept twice. Keep
    # one entry per version, the most present.
    info_by_artifact_version = {}
    for section in ("activations", "assets", "configurations", "management"):
        for item in declarations.get(section, []):
            try:
                _, artifact_pk = parse_artifact_identifier(item["identifier"])
            except ValueError:
                continue
            artifact_version_pk, status, extra_info, server_token = get_target_artifact_info(item)
            existing = info_by_artifact_version.get(artifact_version_pk)
            if existing is not None:
                logger.warning("Duplicate artifact version %s in status report (server tokens %s and %s)",
                               artifact_version_pk, existing[4], server_token)
                if status.presence_rank <= existing[2].presence_rank:
                    continue
            info_by_artifact_version[artifact_version_pk] = (
                artifact_pk, artifact_version_pk, status, extra_info, server_token,
            )
    return list(info_by_artifact_version.values())
