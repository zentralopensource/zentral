import logging
from django.core.cache import cache
from django.db import transaction
from zentral.contrib.inventory.models import MachineGroup, MachineSnapshot, MachineSnapshotCommit, Taxonomy
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_yield_events, set_machine_taxonomy_tags
from zentral.contrib.jamf.api_client import APIClient, APIClientError
from zentral.core.events import event_cls_from_type
from zentral.core.secret_engines import decrypt_str, DecryptionError


logger = logging.getLogger("zentral.contrib.jamf.preprocessors.webhook")


class WebhookEventPreprocessor(object):
    routing_key = "jamf_events"
    _policy_cache_timeout = 5 * 60  # in seconds how long the policies general information are cached
    _policy_cache_stub = "PLEASE_RETRY"

    def __init__(self):
        self.clients = {}
        self.taxonomies = {}

    def _get_client(self, jamf_instance_d):
        key = (jamf_instance_d["pk"], jamf_instance_d["version"])
        client = self.clients.get(key)
        if not client:
            password = jamf_instance_d.pop("password")
            try:
                password = decrypt_str(password, field="password", model="jamf.jamfinstance", pk=jamf_instance_d["pk"])
            except DecryptionError:
                logger.error("Could not decrypt jamf instance %s %s password",
                             jamf_instance_d["pk"], jamf_instance_d["version"])
                # event might have been queued before the secret engines migration
                # allow password as it is in the event
            client = APIClient(password=password, **jamf_instance_d)
            self.clients[key] = client
        return key, client

    def _get_policy_general_info(self, jamf_instance_key, client, policy_id):
        cache_key = "jamf_instance-{}.{}-policy-{}".format(jamf_instance_key[0], jamf_instance_key[1], policy_id)
        policy_d = cache.get(cache_key)
        if policy_d is None:
            try:
                policy_d = client.get_policy_general_info(policy_id)
            except APIClientError:
                # save a stub to block retries for a while
                policy_d = self._policy_cache_stub
            cache.set(cache_key, policy_d, timeout=self._policy_cache_timeout)
        if policy_d != self._policy_cache_stub and isinstance(policy_d, dict):
            return policy_d
        else:
            return None

    def _get_taxonomy(self, taxonomy_id):
        if taxonomy_id not in self.taxonomies:
            try:
                self.taxonomies[taxonomy_id] = Taxonomy.objects.get(pk=taxonomy_id)
            except Taxonomy.DoesNotExist:
                logger.error("Could not get taxonomy %s", taxonomy_id)
        return self.taxonomies.get(taxonomy_id)

    def _is_known_machine(self, client, serial_number):
        kwargs = {"serial_number": serial_number}
        for k, v in client.get_source_d().items():
            kwargs["source__{}".format(k)] = v
        return MachineSnapshotCommit.objects.filter(**kwargs).count() > 0

    def _update_machine(self, client, device_type, jamf_id):
        logger.info("Update machine %s %s %s", client.source_repr, device_type, jamf_id)

        try:
            machine_d, tags = client.get_machine_d_and_tags(device_type, jamf_id)
        except Exception:
            logger.exception("Could not get machine_d and tags. %s %s %s",
                             client.source_repr, device_type, jamf_id)
            return

        serial_number = machine_d.get("serial_number")
        if not serial_number:
            logger.warning("Machine %s %s %s without serial number", client.source_repr, device_type, jamf_id)
            return

        with transaction.atomic():
            yield from commit_machine_snapshot_and_yield_events(machine_d)
            if tags:
                for taxonomy_id, tag_names in tags.items():
                    taxonomy = self._get_taxonomy(taxonomy_id)
                    if taxonomy:
                        # TODO: serialize and deserialize request for MachineTagEvent
                        set_machine_taxonomy_tags(serial_number, taxonomy, tag_names)

    def get_inventory_groups(self, client, device_type, jamf_id, is_smart):
        kwargs = {"reference": client.group_reference(device_type, jamf_id, is_smart)}
        for k, v in client.get_source_d().items():
            kwargs["source__{}".format(k)] = v
        return list(MachineGroup.objects.filter(**kwargs))

    def get_inventory_groups_machine_references(self, inventory_groups):
        for ms_d in MachineSnapshot.objects.current().filter(groups__in=inventory_groups).values("reference"):
            yield ms_d["reference"]

    def _update_group_machines(self, client, device_type, jamf_group_id, is_smart):
        try:
            current_machine_references = set(client.get_group_machine_references(device_type, jamf_group_id))
        except Exception:
            logger.exception("Could not get group machines. %s %s %s",
                             client.source_repr, device_type, jamf_group_id)
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
                yield from self._update_machine(client, device_type, jamf_machine_id)

    def _cleanup_jamf_event(self, raw_event):
        # to avoid indexing errors due to "" used for empty dates for example
        for k, v in list(raw_event.items()):
            if isinstance(v, str):
                raw_event[k] = v = v.strip()
            if v is None or v == "" or v == {}:
                del raw_event[k]
            elif isinstance(v, dict):
                self._cleanup_jamf_event(v)
            elif isinstance(v, list):
                for vc in v:
                    if isinstance(vc, dict):
                        self._cleanup_jamf_event(vc)

    def process_raw_event(self, raw_event):
        jamf_instance_d = raw_event["jamf_instance"]
        jamf_instance_key, client = self._get_client(jamf_instance_d)

        event_type = raw_event["event_type"]
        jamf_event = raw_event["jamf_event"]

        self._cleanup_jamf_event(jamf_event)

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
            yield from self._update_group_machines(client, device_type, jamf_group_id, is_smart)
        elif event_type == "jamf_computer_policy_finished":
            policy_id = jamf_event["policyId"]
            policy_d = self._get_policy_general_info(jamf_instance_key, client, policy_id)
            if policy_d:
                jamf_event["policy"] = policy_d
            else:
                logger.error("Could not get policy %s/%s general information", jamf_instance_key, policy_id)
        else:
            # enrich jamf event ?
            pass

        serial_number = raw_event.get("serial_number")

        # machine needs update ?
        if event_type == "jamf_computer_inventory_completed" \
           or (serial_number and not self._is_known_machine(client, serial_number)):
            device_type = raw_event.get("device_type")
            jamf_machine_id = raw_event.get("jamf_id")
            yield from self._update_machine(client, device_type, jamf_machine_id)

        # yield jamf event
        event_cls = event_cls_from_type(event_type)
        yield from event_cls.build_from_machine_request_payloads(
            serial_number,
            raw_event["request"]["user_agent"],
            raw_event["request"]["ip"],
            [jamf_event],
            observer=raw_event.pop("observer", None)
        )
