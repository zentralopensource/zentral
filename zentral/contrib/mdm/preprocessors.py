import logging
from django.core.cache import cache
from zentral.core.events.base import EventMetadata, EventRequest
from zentral.core.incidents.models import Severity
from .apns import send_enrolled_device_notification
from .apps_books import (associate_location_asset, disassociate_location_asset,
                         get_otf_association_cache_key,
                         location_cache, update_location_asset_counts)
from .events import (AssetCountNotificationEvent,
                     AssetAssociationEvent, AssetAssociationErrorEvent,
                     AssetDisassociationEvent, AssetDisassociationErrorEvent,
                     AssetRevocationEvent, AssetRevocationErrorEvent)
from .incidents import MDMAssetAssociationIncident, MDMAssetDisassociationIncident, MDMAssetRevocationIncident
from .models import EnrolledDevice


logger = logging.getLogger("zentral.contrib.mdm.preprocessors")


class AppsBooksNotificationPreprocessor:
    routing_key = "mdm_apps_books_notification"

    def _get_location_and_client(self, raw_event):
        mdm_info_id = raw_event.get("location", {}).get("mdm_info_id")
        if mdm_info_id:
            try:
                return location_cache.get(mdm_info_id)
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

    def _process_asset_count_notification(self, location, client, notification_id, raw_event):
        data = raw_event["data"]
        adam_id = data["notification"]["adamId"]
        pricing_param = data["notification"]["pricingParam"]
        count_delta = int(data["notification"]["countDelta"])

        # notification event
        yield AssetCountNotificationEvent(
            self._get_event_metadata(raw_event),
            {"asset": {"adam_id": adam_id,
                       "pricing_param": pricing_param},
             "location": location.serialize_for_event(),
             "count_delta": count_delta,
             "notification_id": notification_id}
        )

        # asset update events
        yield from update_location_asset_counts(
            location, client, adam_id, pricing_param,
            {"available_count": count_delta,
             "total_count": count_delta},
            notification_id
        )

    def _process_asset_management_notification(self, location, client, notification_id, raw_event):
        notification = raw_event["data"]["notification"]
        operation = notification["type"]
        success = notification["result"] == "SUCCESS"
        update_func = None
        if operation == "ASSOCIATE":
            if success:
                event_cls = AssetAssociationEvent
                update_func = associate_location_asset
            else:
                event_cls = AssetAssociationErrorEvent
            incident_cls = MDMAssetAssociationIncident
        elif operation == "DISASSOCIATE":
            if success:
                event_cls = AssetDisassociationEvent
                update_func = disassociate_location_asset
            else:
                event_cls = AssetDisassociationErrorEvent
            incident_cls = MDMAssetDisassociationIncident
        elif operation == "REVOKE":
            if success:
                event_cls = AssetRevocationEvent
                update_func = disassociate_location_asset
            else:
                event_cls = AssetRevocationErrorEvent
            incident_cls = MDMAssetRevocationIncident
        else:
            logger.error("Unknown ASSET_MANAGEMENT notification type")
            return
        event_metadata = self._get_event_metadata(raw_event)
        payload = {
            "location": location.serialize_for_event(),
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
        assignments = {}
        for assignment in notification.get("assignments", []):
            adam_id = assignment["adamId"]
            pricing_param = assignment["pricingParam"]
            serial_number = assignment.get("serialNumber")
            if not serial_number:
                # should never happen, see subscriptions
                logger.warning("assignment without serial number")
                continue
            if success:
                assignments.setdefault((adam_id, pricing_param), []).append(serial_number)
            else:
                logger.error("Could not %s adamId %s to %s", operation, adam_id, serial_number)
            event_metadata.machine_serial_number = serial_number
            event_metadata.incident_updates = [
                incident_cls.build_incident_update(
                    location, adam_id, pricing_param,
                    Severity.NONE if success else Severity.MAJOR
                )
            ]
            payload["asset"] = {
                "adam_id": adam_id,
                "pricing_param": pricing_param,
            }
            yield event_cls(event_metadata, payload)
            event_metadata.index += 1
        if not update_func or not assignments:
            return
        notify_devices = (
            update_func == associate_location_asset
            and event_id
            and cache.get(get_otf_association_cache_key(event_id))
        )
        devices_to_notify = set()
        for (adam_id, pricing_param), serial_numbers in assignments.items():
            yield from update_func(
                location, client,
                adam_id, pricing_param, serial_numbers,
                event_id, notification_id
            )
            if notify_devices:
                devices_to_notify.update(serial_numbers)
        if devices_to_notify:
            for enrolled_device in (EnrolledDevice.objects
                                                  .select_related("push_certificate")
                                                  .filter(serial_number__in=devices_to_notify)):
                send_enrolled_device_notification(enrolled_device)

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
        location, client = self._get_location_and_client(raw_event)
        if not location:
            logger.error("Unknown location")
            return
        if notification_type == "ASSET_COUNT":
            yield from self._process_asset_count_notification(location, client, notification_id, raw_event)
        elif notification_type == "ASSET_MANAGEMENT":
            yield from self._process_asset_management_notification(location, client, notification_id, raw_event)


def get_preprocessors():
    yield AppsBooksNotificationPreprocessor()
