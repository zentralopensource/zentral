import logging
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent

logger = logging.getLogger('zentral.contrib.jss.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "jss"}


JSS_EVENTS = {"ComputerAdded": ("computer_added", False),
              "ComputerCheckIn": ("computer_checkin", True),
              "ComputerInventoryCompleted": ("computer_inventory_completed", True),
              "ComputerPolicyFinished": ("computer_policy_finished", True),
              "ComputerPushCapabilityChanged": ("computer_push_capability_changed", False),
              "JSSShutdown": ("shutdown", False),
              "JSSStartup": ("startup", False),
              "MobileDeviceCheckIn": ("mobile_device_checkin", True),
              "MobileDeviceCommandCompleted": ("mobile_device_command_completed", True),
              "MobileDeviceEnrolled": ("mobile_device_enrolled", True),
              "MobileDevicePushSent": ("mobile_device_push_sent", False),
              "MobileDeviceUnEnrolled": ("mobile_device_unenrolled", False),
              "PatchSoftwareTitleUpdated": ("patch_software_title_updated", False),
              "PushSent": ("push_sent", False),
              "RestAPIOperation": ("rest_api_operation", False),
              "SCEPChallenge": ("scep_challenge", False),
              "SmartGroupComputerMembershipChange": ("smart_group_computer_membership_change", False),
              "SmartGroupMobileDeviceMembershipChange": ("smart_group_mobile_device_membership_change", False)}


for jss_event, (event_subtype, is_heartbeat) in JSS_EVENTS.items():
    event_type = 'jss_{}'.format(event_subtype)
    event_class_name = "".join(s.title() for s in event_type.split('_'))
    tags = ['jss']
    if is_heartbeat:
        tags.append('heartbeat')
    event_class = type(event_class_name, (BaseEvent,), {'event_type': event_type, 'tags': tags})
    register_event_type(event_class)


def post_jss_event(user_agent, ip, data):
    event_cls = event_cls_from_type('jss_{}'.format(JSS_EVENTS[data["webhook"]["webhookEvent"]][0]))
    payload = data["event"]
    msn = payload.get("serialNumber", None)
    event_cls.post_machine_request_payloads(msn, user_agent, ip, [payload])
