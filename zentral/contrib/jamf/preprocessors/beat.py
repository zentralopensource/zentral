import json
import logging
import re
from dateutil import parser
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.filebeat.utils import get_user_agent_and_ip_address_from_raw_event
from zentral.contrib.jamf.events import JAMFAccessEvent, JAMFChangeManagementEvent, JAMFSoftwareServerEvent
from zentral.core.events.base import EventMetadata, EventRequest


logger = logging.getLogger("zentral.contrib.jamf.preprocessors.beat")


class BeatPreprocessor(object):
    routing_key = "jamf_logs"
    USER_RE = re.compile(r'^(?P<name>.*) \(ID: (?P<id>\d+)\)$')
    OBJECT_INFO_SEP_RE = re.compile("[ \.]{2,}")

    def get_created_at(self, raw_event_d):
        return parser.parse(raw_event_d["@timestamp"])

    def build_change_management_event(self, raw_event_d, user_agent, ip_address):
        object_type = raw_event_d.get("object", None)
        action = raw_event_d.get("action", None)
        if object_type is None or action is None:
            logger.error("Could not build change management event %s", raw_event_d)
            return
        payload = {"action": action,
                   "object": {"type": object_type}}
        # access denied
        access_denied = raw_event_d.get("access_denied", False)
        if access_denied:
            payload["access_denied"] = True
        # object
        object_id = None
        for object_info_line in raw_event_d.get("object_info", "").splitlines():
            object_info_line = object_info_line.strip()
            if not object_info_line or object_info_line.startswith("-"):
                # empty line or line separator
                continue
            try:
                k, v = self.OBJECT_INFO_SEP_RE.split(object_info_line, 1)
            except ValueError:
                logger.warning("Unable to parse object info line '%s'", object_info_line)
            else:
                if not v:
                    continue
                k = k.lower().replace(" ", "_")
                if k == "id":
                    v = object_id = int(v)
                elif k == "type":
                    logger.warning("Object info type key conflict")
                    continue
                elif v == "false":
                    v = False
                elif v == "true":
                    v = True
                payload["object"][k] = v
        # user
        user_m = self.USER_RE.match(raw_event_d["user"])
        if user_m:
            payload["user"] = {"id": int(user_m.group("id")),
                               "name": user_m.group("name")}
        # machine serial number
        machine_serial_number = None
        device_type = None
        if object_type == "Mobile Device":
            device_type = "mobile_device"
        elif object_type == "Computer":
            device_type = "computer"
        if device_type and object_id:
            kwargs = {"reference": "{},{}".format(device_type, object_id),
                      "source__module": "zentral.contrib.jamf",
                      "source__name": "jamf",
                      "source__config": payload["jamf_instance"]}
            try:
                ms = MachineSnapshot.objects.filter(**kwargs).order_by('-id')[0]
            except IndexError:
                pass
            else:
                machine_serial_number = ms.serial_number
        # event
        metadata = EventMetadata(JAMFChangeManagementEvent.event_type,
                                 machine_serial_number=machine_serial_number,
                                 request=EventRequest(user_agent, ip_address),
                                 created_at=self.get_created_at(raw_event_d),
                                 tags=JAMFChangeManagementEvent.tags)
        return JAMFChangeManagementEvent(metadata, payload)

    def build_software_server_event(self, raw_event_d, user_agent, ip_address):
        payload = {}
        for p_attr, re_attr in (("log_level", "log_level"),
                                ("info_1", "info_1"),
                                ("component", "component"),
                                ("message", "cleaned_message")):
            v = raw_event_d.get(re_attr, None)
            if v:
                payload[p_attr] = v
            else:
                logger.warning("Missing software server event attr %s.", re_attr)
        if not payload:
            logger.error("Could not build software server event %s", raw_event_d)
            return None
        else:
            # event
            metadata = EventMetadata(JAMFSoftwareServerEvent.event_type,
                                     created_at=self.get_created_at(raw_event_d),
                                     request=EventRequest(user_agent, ip_address),
                                     tags=JAMFSoftwareServerEvent.tags)
            return JAMFSoftwareServerEvent(metadata, payload)

    def build_access_event(self, raw_event_d, user_agent, ip_address):
        # payload
        try:
            payload = {attr: raw_event_d[attr] for attr in ("entry_point", "username", "status", "ip_address")}
        except KeyError:
            logger.error("Could not build access event %s", raw_event_d)
            return
        # event
        metadata = EventMetadata(JAMFAccessEvent.event_type,
                                 created_at=self.get_created_at(raw_event_d),
                                 request=EventRequest(user_agent, ip_address),
                                 tags=JAMFAccessEvent.tags)
        return JAMFAccessEvent(metadata, payload)

    def process_raw_event(self, raw_event):
        raw_event_d = json.loads(raw_event)
        user_agent, ip_address = get_user_agent_and_ip_address_from_raw_event(raw_event_d)
        zentral_log_type = raw_event_d["zentral_log_type"]
        event = None
        if zentral_log_type == "zentral.contrib.jamf.jamf_change_management":
            event = self.build_change_management_event(raw_event_d, user_agent, ip_address)
        elif zentral_log_type == "zentral.contrib.jamf.jamf_software_server":
            event = self.build_software_server_event(raw_event_d, user_agent, ip_address)
        elif zentral_log_type == "zentral.contrib.jamf.jss_access":
            event = self.build_access_event(raw_event_d, user_agent, ip_address)
        else:
            logger.warning("Unknown zentral_log_type %s", zentral_log_type)
            return
        if event:
            yield event
