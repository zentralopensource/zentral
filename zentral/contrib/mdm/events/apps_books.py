from datetime import datetime
import logging
from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent
from zentral.core.queues import queues


logger = logging.getLogger('zentral.contrib.mdm.events.apps_books')


# common


class BaseAppsBooksEvent(BaseEvent):
    namespace = "apps_books"

    def get_linked_objects_keys(self):
        keys = {}
        # asset
        asset = self.payload.get("asset", {})
        adam_id = asset.get("adam_id")
        pricing_param = asset.get("pricing_param")
        if adam_id and pricing_param:
            keys["mdm_asset"] = [(adam_id, pricing_param)]
        # server token
        server_token_pk = self.payload.get("server_token", {}).get("pk")
        if server_token_pk:
            keys["mdm_server_token"] = [(server_token_pk,)]
        return keys


# apps & books notifications events


class BaseAppsBooksNotificationEvent(BaseAppsBooksEvent):
    tags = ["mdm", "apps_books", "apps_books_notification"]


class AssetCountNotificationEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_count_notification"


register_event_type(AssetCountNotificationEvent)


class AssetAssociationEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_association"


register_event_type(AssetAssociationEvent)


class AssetAssociationErrorEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_association_error"


register_event_type(AssetAssociationErrorEvent)


class AssetDisassociationEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_disassociation"


register_event_type(AssetDisassociationEvent)


class AssetDisassociationErrorEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_disassociation_error"


register_event_type(AssetDisassociationErrorEvent)


class AssetRevocationEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_revocation"


register_event_type(AssetRevocationEvent)


class AssetRevocationErrorEvent(BaseAppsBooksNotificationEvent):
    event_type = "mdm_asset_revocation_error"


register_event_type(AssetRevocationErrorEvent)


# asset events


class BaseAssetEvent(BaseAppsBooksEvent):
    tags = ["mdm", "apps_books", "apps_books_asset"]


class AssetCreatedEvent(BaseAssetEvent):
    event_type = "mdm_asset_created"


register_event_type(AssetCreatedEvent)


class AssetUpdatedEvent(BaseAssetEvent):
    event_type = "mdm_asset_updated"


register_event_type(AssetUpdatedEvent)


class ServerTokenAssetCreatedEvent(BaseAssetEvent):
    event_type = "mdm_server_token_asset_created"


register_event_type(ServerTokenAssetCreatedEvent)


class ServerTokenAssetUpdatedEvent(BaseAssetEvent):
    event_type = "mdm_server_token_asset_updated"


register_event_type(ServerTokenAssetUpdatedEvent)


class DeviceAssignmentRequestEvent(BaseAssetEvent):
    event_type = "mdm_device_assignment_request"


register_event_type(DeviceAssignmentRequestEvent)


class DeviceAssignmentRequestErrorEvent(BaseAssetEvent):
    event_type = "mdm_device_assignment_request_error"


register_event_type(DeviceAssignmentRequestErrorEvent)


class DeviceAssignmentCreatedEvent(BaseAssetEvent):
    event_type = "mdm_device_assignment_created"


register_event_type(DeviceAssignmentCreatedEvent)


class DeviceAssignmentDeletedEvent(BaseAssetEvent):
    event_type = "mdm_device_assignment_deleted"


register_event_type(DeviceAssignmentDeletedEvent)


# notification raw event


def post_apps_books_notification_event(server_token, user_agent, ip, data):
    raw_event = {
        "data": data,
        "metadata": {
            "request": {
                "user_agent": user_agent,
                "ip": ip,
            },
            "created_at": datetime.utcnow().isoformat(),
        },
        "server_token": {
            "pk": server_token.pk,
            "notification_auth_token_id": server_token.notification_auth_token_id,
        }
    }
    logger.debug("Post mdm_apps_books_notification raw event")
    queues.post_raw_event("mdm_apps_books_notification", raw_event)
