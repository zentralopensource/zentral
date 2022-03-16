import logging
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent
from zentral.core.queues import queues
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.jamf.models import JamfInstance

logger = logging.getLogger('zentral.contrib.jamf.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "jamf"}


JAMF_EVENTS = {"ComputerAdded": ("computer_added", False, None),
               "ComputerCheckIn": ("computer_checkin", True,
                                   "checkin_heartbeat_timeout"),
               "ComputerInventoryCompleted": ("computer_inventory_completed", True,
                                              "inventory_completed_heartbeat_timeout"),
               "ComputerPatchPolicyCompleted": ("computer_patch_policy_completed", True, None),
               "ComputerPolicyFinished": ("computer_policy_finished", True, None),
               "ComputerPushCapabilityChanged": ("computer_push_capability_changed", False, None),
               "DeviceAddedToDEP": ("device_added_to_dep", False, None),
               "JSSShutdown": ("shutdown", False, None),
               "JSSStartup": ("startup", False, None),
               "MobileDeviceCheckIn": ("mobile_device_checkin", True, None),
               "MobileDeviceCommandCompleted": ("mobile_device_command_completed", True, None),
               "MobileDeviceEnrolled": ("mobile_device_enrolled", True, None),
               "MobileDevicePushSent": ("mobile_device_push_sent", False, None),
               "MobileDeviceUnEnrolled": ("mobile_device_unenrolled", False, None),
               "PatchSoftwareTitleUpdated": ("patch_software_title_updated", False, None),
               "PushSent": ("push_sent", False, None),
               "RestAPIOperation": ("rest_api_operation", False, None),
               "SCEPChallenge": ("scep_challenge", False, None),
               "SmartGroupComputerMembershipChange": ("smart_group_computer_membership_change", False, None),
               "SmartGroupMobileDeviceMembershipChange": ("smart_group_mobile_device_membership_change", False, None)}


def make_get_machine_heartbeat_timeout(instance_attr):
    def get_machine_heartbeat_timeout(cls, serial_number):
        ms = MachineSnapshot.objects.select_related("source").filter(serial_number=serial_number,
                                                                     source__name="jamf").order_by("-id").first()
        if not ms:
            logger.warning("No Jamf machine snapshot found for serial number %s", serial_number)
            return
        try:
            instance = JamfInstance.objects.get(**ms.source.config)
        except JamfInstance.MultipleObjectsReturned:
            logger.warning("Multiple JamfInstances found for serial number %s", serial_number)
        except (JamfInstance.DoesNotExist, MachineSnapshot.DoesNotExist):
            logger.warning("No JamfInstance found for serial number %s", serial_number)
        else:
            return getattr(instance, instance_attr, None)
    return classmethod(get_machine_heartbeat_timeout)


for jamf_event, (event_subtype, is_heartbeat, timeout_attr) in JAMF_EVENTS.items():
    event_type = 'jamf_{}'.format(event_subtype)
    event_class_name = "".join(s.title() for s in event_type.split('_'))
    tags = ['jamf', 'jamf_webhook']
    if is_heartbeat:
        tags.append('heartbeat')
    event_class_attrs = {'event_type': event_type, 'tags': tags}
    if timeout_attr:
        event_class_attrs["get_machine_heartbeat_timeout"] = make_get_machine_heartbeat_timeout(timeout_attr)
    event_class = type(event_class_name, (BaseEvent,), event_class_attrs)
    register_event_type(event_class)


class JAMFChangeManagementEvent(BaseEvent):
    event_type = "jamf_change_management"
    tags = ["jamf", "jamf_beat"]
    payload_aggregations = [
        ("jamf_instance.host", {"type": "terms", "bucket_number": 10, "label": "Hosts"}),
        ("action", {"type": "terms", "bucket_number": 10, "label": "Actions"}),
        ("object.type", {"type": "terms", "bucket_number": 10, "label": "Object types"}),
    ]


register_event_type(JAMFChangeManagementEvent)


class JAMFSoftwareServerEvent(BaseEvent):
    event_type = "jamf_software_server"
    tags = ["jamf", "jamf_beat"]
    payload_aggregations = [
        ("log_level", {"type": "terms", "bucket_number": 10, "label": "Log levels"}),
        ("component", {"type": "terms", "bucket_number": 10, "label": "Components"}),
        ("jamf_instance.host", {"type": "terms", "bucket_number": 10, "label": "Hosts"}),
    ]


register_event_type(JAMFSoftwareServerEvent)


class JAMFAccessEvent(BaseEvent):
    event_type = "jamf_access"
    tags = ["jamf", "jamf_beat"]
    payload_aggregations = [
        ("status", {"type": "terms", "bucket_number": 10, "label": "Statuses"}),
        ("entry_point", {"type": "terms", "bucket_number": 10, "label": "Entry points"}),
    ]


register_event_type(JAMFAccessEvent)


class JAMFClientEvent(BaseEvent):
    event_type = "jamf_client"
    tags = ["jamf", "jamf_beat"]


register_event_type(JAMFClientEvent)


def post_jamf_webhook_event(jamf_instance, user_agent, ip, data):
    jamf_event = data["webhook"]["webhookEvent"]
    event_type = 'jamf_{}'.format(JAMF_EVENTS[jamf_event][0])
    payload = data["event"]

    # device event ?
    device_type = None
    if jamf_event.startswith("Computer"):
        device_type = "computer"
    elif jamf_event.startswith("MobileDevice"):
        device_type = "mobile_device"

    observer_dict = jamf_instance.observer_dict()

    if device_type is not None \
       or event_type == "jamf_smart_group_computer_membership_change" \
       or event_type == "jamf_smart_group_mobile_device_membership_change":
        # event needs preprocessing
        raw_event = {"request": {"user_agent": user_agent,
                                 "ip": ip},
                     "observer": observer_dict,
                     "event_type": event_type,
                     "jamf_instance": jamf_instance.serialize(),
                     "jamf_event": payload}
        if device_type:
            try:
                jamf_id = payload["computer"]["jssID"]
                serial_number = payload["computer"]["serialNumber"]
            except KeyError:
                jamf_id = payload["jssID"]
                serial_number = payload["serialNumber"]
            raw_event.update({
                "device_type": device_type,
                "jamf_id": jamf_id,
                "serial_number": serial_number,
            })
        queues.post_raw_event("jamf_events", raw_event)
    else:
        # event doesn't need preprocessing
        event_cls = event_cls_from_type(event_type)
        msn = payload.get("serialNumber", None)
        event_cls.post_machine_request_payloads(msn, user_agent, ip, [payload], observer=observer_dict)
