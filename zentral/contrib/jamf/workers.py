import json
import logging
import re
from dateutil import parser
from zentral.contrib.inventory.models import MachineGroup, MachineSnapshot, MachineSnapshotCommit
from zentral.contrib.inventory.utils import inventory_events_from_machine_snapshot_commit
from zentral.core.events import event_cls_from_type
from zentral.core.events.base import EventMetadata
from zentral.core.queues import queues
from zentral.contrib.jamf.events import JAMFChangeManagementEvent
from .api_client import APIClient, APIClientError


logger = logging.getLogger("zentral.contrib.jamf.preprocessor")


class WebhookEventPreprocessor(object):
    name = "jamf webhook events preprocessor"
    input_queue_name = "jamf_events"

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
        except APIClientError as e:
            logger.error("Could not get machine_d. %s %s %s", client.get_source_d(), device_type, jamf_id)
        else:
            try:
                msc, ms = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(machine_d)
            except:
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

    def get_inventory_group(self, client, device_type, jamf_id, is_smart):
        kwargs = {"reference": client.group_reference(device_type, jamf_id, is_smart)}
        for k, v in client.get_source_d().items():
            kwargs["source__{}".format(k)] = v
        try:
            return MachineGroup.objects.get(**kwargs)
        except MachineGroup.DoesNotExist:
            return None

    def get_inventory_group_machine_references(self, inventory_group):
        for ms_d in MachineSnapshot.objects.current().filter(groups=inventory_group).values("reference"):
            yield ms_d["reference"]

    def update_group_machines(self, client, device_type, jamf_group_id, is_smart):
        current_machine_references = set(client.get_group_machine_references(device_type, jamf_group_id))
        inventory_group = self.get_inventory_group(client, device_type, jamf_group_id, is_smart)
        if not inventory_group:
            # unknown group. update all machines
            references_iterator = current_machine_references
        else:
            # known group. update symmetric difference
            inventory_machine_references = set(self.get_inventory_group_machine_references(inventory_group))
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
        elif event_type == "jamf_computer_push_capability_changed":
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
    name = "jamf beats preprocessor"
    input_queue_name = "jamf_beats"
    USER_RE = re.compile(r'^(?P<name>.*) \(ID: (?P<id>\d+)\)$')

    def build_change_management_event(self, raw_event_d):
        object_type = raw_event_d["object"]
        payload = {"action": raw_event_d["action"],
                   "object": {"type": object_type}}
        # object
        object_id = None
        object_info_lines = raw_event_d.get("object_info", "").splitlines()
        if object_info_lines:
            l1 = object_info_lines[0].strip()
            if l1.startswith("ID"):
                payload["object"]["id"] = object_id = int(l1.split()[-1])
            if len(object_info_lines) > 1:
                l2 = object_info_lines[1].strip()
                if l2.startswith("Name"):
                    payload["object"]["name"] = " ".join(l2.split()[2:])
        # jamf instance
        jamf_instance = raw_event_d["fields"]["jamf_instance"]
        jamf_instance.setdefault("path", "/JSSResource")
        jamf_instance.setdefault("port", 8443)
        payload["jamf_instance"] = jamf_instance
        # user
        user_m = self.USER_RE.match(raw_event_d["user"])
        if user_m:
            payload["user"] = {"id": int(user_m.group("id")),
                               "name": user_m.group("name")}
        # timestamp
        created_at = parser.parse(raw_event_d["@timestamp"])
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
                      "source__config": jamf_instance}
            try:
                ms = MachineSnapshot.objects.filter(**kwargs).order_by('-id')[0]
            except IndexError:
                pass
            else:
                machine_serial_number = ms.serial_number
        # event
        metadata = EventMetadata(JAMFChangeManagementEvent.event_type,
                                 machine_serial_number=machine_serial_number,
                                 created_at=created_at,
                                 tags=JAMFChangeManagementEvent.tags)
        return JAMFChangeManagementEvent(metadata, payload)

    def process_raw_event(self, raw_event):
        raw_event_d = json.loads(raw_event)
        raw_event_type = raw_event_d["type"]
        if raw_event_type == "jamf_change_management":
            yield self.build_change_management_event(raw_event_d)
        else:
            logger.warning("Unknown event type %s", raw_event_type)


def get_workers():
    yield queues.get_preprocessor_worker(WebhookEventPreprocessor())
    yield queues.get_preprocessor_worker(BeatPreprocessor())
