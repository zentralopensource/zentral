from .data_asset import build_data_asset
from .declaration import build_declaration
from .exceptions import DeclarationError
from .legacy_profile import build_legacy_profile
from .management import build_target_management_status_subscriptions
from .software_update import build_specific_software_update_enforcement


__all__ = ["build_declaration_response"]


def build_declaration_response(endpoint, event_payload, enrollment_session, target):
    _, declaration_type, declaration_identifier = endpoint.split("/")
    event_payload["declaration_type"] = declaration_type
    event_payload["declaration_identifier"] = declaration_identifier
    if declaration_identifier.endswith("management-status-subscriptions"):
        return build_target_management_status_subscriptions(target)
    elif declaration_identifier.endswith("activation"):
        return target.activation
    elif declaration_identifier.endswith("softwareupdate-enforcement-specific"):
        return build_specific_software_update_enforcement(target)
    elif ".declaration." in declaration_identifier:
        return build_declaration(enrollment_session, target, declaration_identifier)
    elif ".data-asset." in declaration_identifier:
        return build_data_asset(enrollment_session, target, declaration_identifier)
    elif ".legacy-profile." in declaration_identifier:
        return build_legacy_profile(enrollment_session, target, declaration_identifier)
    else:
        raise DeclarationError("Unknown declaration")
