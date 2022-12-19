import logging
from django.core.cache import cache
from zentral.core.events.base import EventMetadata, EventRequest
from zentral.core.incidents.models import Severity
from .apps_books import (associate_server_token_asset, disassociate_server_token_asset,
                         clear_on_the_fly_assignment,
                         server_token_cache, update_server_token_asset_counts)
from .events import (AssetCountNotificationEvent,
                     AssetAssociationEvent, AssetAssociationErrorEvent,
                     AssetDisassociationEvent, AssetDisassociationErrorEvent,
                     AssetRevocationEvent, AssetRevocationErrorEvent)
from .incidents import MDMAssetAssociationIncident, MDMAssetDisassociationIncident, MDMAssetRevocationIncident


logger = logging.getLogger("zentral.contrib.mdm.preprocessors")


class AppsBooksNotificationPreprocessor:
    routing_key = "mdm_apps_books_notification"

    def _get_server_token_and_client(self, raw_event):
        mdm_info_id = raw_event.get("server_token", {}).get("mdm_info_id")
        if mdm_info_id:
            try:
                return server_token_cache.get(mdm_info_id)
            except KeyError:
                logger.error("Unknown MDM Info ID")
                return None, None
        else:
            logger.error("Missing or bad MDM Info ID")
            return None, None

    def _get_event_metadata(self, raw_event):
        metadata = raw_event["metadata"]
        return EventMetadata(request=EventRequest(**metadata["request"]),
                             created_at=metadata["created_at"])

    def _process_asset_count_notification(self, server_token, client, notification_id, raw_event):
        data = raw_event["data"]
        adam_id = data["notification"]["adamId"]
        pricing_param = data["notification"]["pricingParam"]
        count_delta = int(data["notification"]["countDelta"])

        # notification event
        yield AssetCountNotificationEvent(
            self._get_event_metadata(raw_event),
            {"asset": {"adam_id": adam_id,
                       "pricing_param": pricing_param},
             "server_token": server_token.serialize_for_event(),
             "count_delta": count_delta,
             "notification_id": notification_id}
        )

        # asset update events
        yield from update_server_token_asset_counts(
            server_token, client, adam_id, pricing_param,
            {"available_count": count_delta,
             "total_count": count_delta},
            notification_id
        )

    def _process_asset_management_notification(self, server_token, client, notification_id, raw_event):
        notification = raw_event["data"]["notification"]
        operation = notification["type"]
        success = notification["result"] == "SUCCESS"
        update_func = None
        if operation == "ASSOCIATE":
            if success:
                event_cls = AssetAssociationEvent
                update_func = associate_server_token_asset
            else:
                event_cls = AssetAssociationErrorEvent
            incident_cls = MDMAssetAssociationIncident
        elif operation == "DISASSOCIATE":
            if success:
                event_cls = AssetDisassociationEvent
                update_func = disassociate_server_token_asset
            else:
                event_cls = AssetDisassociationErrorEvent
            incident_cls = MDMAssetDisassociationIncident
        elif operation == "REVOKE":
            if success:
                event_cls = AssetRevocationEvent
                update_func = disassociate_server_token_asset
            else:
                event_cls = AssetRevocationErrorEvent
            incident_cls = MDMAssetRevocationIncident
        else:
            logger.error("Unknown ASSET_MANAGEMENT notification type")
            return
        event_metadata = self._get_event_metadata(raw_event)
        payload = {
            "server_token": server_token.serialize_for_event(),
            "notification_id": notification_id,
        }
        event_id = notification.get("eventId")
        if event_id:
            payload["event_id"] = event_id
        error = notification.get("error")
        if error:
            payload["error"] = {
                "message": error.get("errorMessage"),
                "number": error.get("errorNumber"),
            }
        serial_numbers = set()
        for assignment in notification.get("assignments", []):
            adam_id = assignment["adamId"]
            pricing_param = assignment["pricingParam"]
            serial_number = assignment.get("serialNumber")
            if not serial_number:
                # should never happen, see subscriptions
                logger.warning("assignment without serial number")
                continue
            if success:
                serial_numbers.add(serial_number)
            elif operation == "ASSOCIATE":
                # could not associate, remove the on-the-fly assignment if it exists
                clear_on_the_fly_assignment(
                    server_token, serial_number, adam_id, pricing_param, "associate error"
                )
            event_metadata.machine_serial_number = serial_number
            event_metadata.incident_updates = [
                incident_cls.build_incident_update(
                    server_token, adam_id, pricing_param,
                    Severity.NONE if success else Severity.MAJOR
                )
            ]
            payload["asset"] = {
                "adam_id": adam_id,
                "pricing_param": pricing_param,
            }
            yield event_cls(event_metadata, payload)
            event_metadata.index += 1
        if update_func and serial_numbers:
            yield from update_func(
                server_token, client,
                adam_id, pricing_param, serial_numbers,
                event_id, notification_id
            )

    def process_raw_event(self, raw_event):
        data = raw_event.get("data")
        if not isinstance(data, dict):
            logger.error("Bad raw event")
            return
        notification_type = data.get("notificationType")
        if not isinstance(notification_type, str):
            logger.error("Missing or bad notification type")
            return
        if notification_type not in ("ASSET_COUNT", "ASSET_MANAGEMENT"):
            logger.warning("Unknown notification type: %s", notification_type)
            return
        notification_id = data["notificationId"]
        if not cache.add(f"apps_books_notification_{notification_id}", 1, timeout=600):  # TODO hard-coded
            logger.warning("Notification %s already received", notification_id)
            # TODO retry on error?
            return
        server_token, client = self._get_server_token_and_client(raw_event)
        if not server_token:
            logger.error("Unknown server token")
            return
        if notification_type == "ASSET_COUNT":
            yield from self._process_asset_count_notification(server_token, client, notification_id, raw_event)
        elif notification_type == "ASSET_MANAGEMENT":
            yield from self._process_asset_management_notification(server_token, client, notification_id, raw_event)


def get_preprocessors():
    yield AppsBooksNotificationPreprocessor()
