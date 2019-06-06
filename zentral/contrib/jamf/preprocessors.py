import json
import logging
import re
from dateutil import parser
from zentral.contrib.inventory.models import MachineGroup, MachineSnapshot, MachineSnapshotCommit
from zentral.contrib.inventory.utils import inventory_events_from_machine_snapshot_commit
from zentral.core.events import event_cls_from_type
from zentral.core.events.base import EventMetadata, EventRequest
from zentral.contrib.jamf.events import JAMFAccessEvent, JAMFChangeManagementEvent, JAMFSoftwareServerEvent
from zentral.contrib.filebeat.utils import get_user_agent_and_ip_address_from_raw_event
from .api_client import APIClient


logger = logging.getLogger("zentral.contrib.jamf.preprocessors")


class WebhookEventPreprocessor(object):
    routing_key = "jamf_events"

    def __init__(self):
        self.clients = {}

    def get_client(self, jamf_instance_d):
        key = (jamf_instance_d["pk"], jamf_instance_d["version"])
        client = self.clients.get(key)
        if not client:
            client = APIClient(**jamf_instance_d)
            self.clients[key] = client
        return client

    def is_known_machine(self, client, serial_number):
        kwargs = {"serial_number": serial_number}
        for k, v in client.get_source_d().items():
            kwargs["source__{}".format(k)] = v
        return MachineSnapshotCommit.objects.filter(**kwargs).count() > 0

    def update_machine(self, client, device_type, jamf_id):
        logger.info("Update machine %s %s %s", client.get_source_d(), device_type, jamf_id)
        try:
            machine_d = client.get_machine_d(device_type, jamf_id)
        except Exception:
            logger.exception("Could not get machine_d. %s %s %s",
                             client.get_source_d(), device_type, jamf_id)
        else:
            try:
                msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(machine_d)
            except Exception:
                logger.exception("Could not commit machine snapshot")
            else:
                if msc:
                    for idx, (event_type, created_at, payload) in enumerate(
                            inventory_events_from_machine_snapshot_commit(msc)):
                        event_cls = event_cls_from_type(event_type)
                        metadata = EventMetadata(event_cls.event_type,
                                                 machine_serial_number=ms.serial_number,
                                                 index=idx,
                                                 created_at=created_at,
                                                 tags=event_cls.tags)
                        event = event_cls(metadata, payload)
                        yield event

    def get_inventory_groups(self, client, device_type, jamf_id, is_smart):
        kwargs = {"reference": client.group_reference(device_type, jamf_id, is_smart)}
        for k, v in client.get_source_d().items():
            kwargs["source__{}".format(k)] = v
        return list(MachineGroup.objects.filter(**kwargs))

    def get_inventory_groups_machine_references(self, inventory_groups):
        for ms_d in MachineSnapshot.objects.current().filter(groups__in=inventory_groups).values("reference"):
            yield ms_d["reference"]

    def update_group_machines(self, client, device_type, jamf_group_id, is_smart):
        try:
            current_machine_references = set(client.get_group_machine_references(device_type, jamf_group_id))
        except Exception:
            logger.exception("Could not get group machines. %s %s %s",
                             client.get_source_d(), device_type, jamf_group_id)
        else:
            inventory_groups = self.get_inventory_groups(client, device_type, jamf_group_id, is_smart)
            if not inventory_groups:
                # unknown group. update all machines
                references_iterator = current_machine_references
            else:
                # known group. update symmetric difference
                inventory_machine_references = set(self.get_inventory_groups_machine_references(inventory_groups))
                references_iterator = inventory_machine_references ^ current_machine_references
            for reference in references_iterator:
                _, jamf_machine_id = reference.split(",")
                yield from self.update_machine(client, device_type, jamf_machine_id)

    def process_raw_event(self, raw_event):
        jamf_instance_d = raw_event["jamf_instance"]
        client = self.get_client(jamf_instance_d)

        event_type = raw_event["event_type"]
        jamf_event = raw_event["jamf_event"]

        if event_type == "jamf_smart_group_computer_membership_change" \
           or event_type == "jamf_smart_group_mobile_device_membership_change":
            if jamf_event.get("computer"):
                device_type = "computer"
            else:
                device_type = "mobile_device"
            jamf_group_id = jamf_event["jssid"]
            is_smart = jamf_event["smartGroup"]
            # find missing machines and machines still in the group
            # update them
            yield from self.update_group_machines(client, device_type, jamf_group_id, is_smart)
        elif event_type == "jamf_computer_policy_finished":
            try:
                jamf_event["policy"] = client.get_policy_general_info(jamf_event["policyId"])
            except Exception:
                logger.exception("Could not enrich policy finished event")
        else:
            # enrich jamf event ?
            pass

        serial_number = raw_event.get("serial_number")

        # machine needs update ?
        if event_type == "jamf_computer_inventory_completed" \
           or event_type == "jamf_computer_checkin" \
           or event_type == "jamf_mobile_device_checkin" \
           or (serial_number and not self.is_known_machine(client, serial_number)):
            device_type = raw_event.get("device_type")
            jamf_machine_id = raw_event.get("jamf_id")
            yield from self.update_machine(client, device_type, jamf_machine_id)

        # yield jamf event
        event_cls = event_cls_from_type(event_type)
        yield from event_cls.build_from_machine_request_payloads(
            serial_number,
            raw_event["request"]["user_agent"],
            raw_event["request"]["ip"],
            [jamf_event]
        )


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


def get_preprocessors():
    yield WebhookEventPreprocessor()
    yield BeatPreprocessor()
