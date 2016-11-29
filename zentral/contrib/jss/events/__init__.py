import logging
from zentral.core.events import event_cls_from_type, register_event_type
from zentral.core.events.base import BaseEvent

logger = logging.getLogger('zentral.contrib.jss.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "jss"}


JSS_EVENTS = {"ComputerAdded": "computer_added",
              "ComputerCheckIn": "computer_checkin",
              "ComputerInventoryCompleted": "computer_inventory_completed",
              "ComputerPolicyFinished": "computer_policy_finished",
              "ComputerPushCapabilityChanged": "computer_push_capability_changed",
              "JSSShutdown": "shutdown",
              "JSSStartup": "startup",
              "MobileDeviceCheckIn": "mobile_device_checkin",
              "MobileDeviceCommandCompleted": "mobile_device_command_completed",
              "MobileDeviceEnrolled": "mobile_device_enrolled",
              "MobileDevicePushSent": "mobile_device_push_sent",
              "MobileDeviceUnEnrolled": "mobile_device_unenrolled",
              "PatchSoftwareTitleUpdated": "patch_software_title_updated",
              "PushSent": "push_sent",
              "RestAPIOperation": "rest_api_operation",
              "SCEPChallenge": "scep_challenge",
              "SmartGroupComputerMembershipChange": "smart_group_computer_membership_change",
              "SmartGroupMobileDeviceMembershipChange": "smart_group_mobile_device_membership_change"}


for jss_event, event_subtype in JSS_EVENTS.items():
    event_type = 'jss_{}'.format(event_subtype)
    event_class_name = "".join(s.title() for s in event_type.split('_'))
    event_class = type(event_class_name, (BaseEvent,), {'event_type': event_type, 'tags': ['jss']})
    register_event_type(event_class)


def post_jss_event(user_agent, ip, data):
    event_cls = event_cls_from_type('jss_{}'.format(JSS_EVENTS[data["webhook"]["webhookEvent"]]))
    payload = data["event"]
    msn = payload.get("serialNumber", None)
    event_cls.post_machine_request_payloads(msn, user_agent, ip, [payload])
