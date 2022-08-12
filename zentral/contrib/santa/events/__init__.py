from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, EventMetadata, EventRequest, register_event_type
from zentral.contrib.inventory.models import File
from zentral.contrib.santa.models import Bundle, EnrolledMachine, Target
from zentral.utils.certificates import APPLE_DEV_ID_ISSUER_CN, parse_apple_dev_id
from zentral.utils.text import shard


logger = logging.getLogger('zentral.contrib.santa.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "santa"}


class SantaEnrollmentEvent(BaseEvent):
    event_type = "santa_enrollment"
    tags = ["santa"]

    def get_linked_objects_keys(self):
        keys = {}
        configuration = self.payload.get("configuration")
        if configuration:
            keys["santa_configuration"] = [(configuration.get("pk"),)]
        return keys


register_event_type(SantaEnrollmentEvent)


class SantaPreflightEvent(BaseEvent):
    event_type = "santa_preflight"
    tags = ["santa", "heartbeat"]

    @classmethod
    def get_machine_heartbeat_timeout(cls, serial_number):
        enrolled_machines = EnrolledMachine.objects.get_for_serial_number(serial_number)
        count = len(enrolled_machines)
        if not count:
            return
        if count > 1:
            logger.warning("Multiple enrolled machines found for %s", serial_number)
        timeout = 2 * enrolled_machines[0].enrollment.configuration.full_sync_interval
        logger.debug("Santa preflight event heartbeat timeout for machine %s: %s", serial_number, timeout)
        return timeout


register_event_type(SantaPreflightEvent)


class SantaEventEvent(BaseEvent):
    event_type = "santa_event"
    tags = ["santa"]
    payload_aggregations = [
        ("decision", {"type": "terms", "bucket_number": 10, "label": "Decisions"}),
        ("file_bundle_name", {"type": "terms", "bucket_number": 10, "label": "Bundle names"}),
        ("bundles", {"type": "table", "bucket_number": 100, "label": "Bundles",
                     "columns": [("file_bundle_name", "Name"),
                                 ("file_bundle_id", "ID"),
                                 ("file_bundle_path", "File path"),
                                 ("file_bundle_version_string", "Version str.")]}),
    ]

    def get_notification_context(self, probe):
        ctx = super().get_notification_context(probe)
        if 'decision' in self.payload:
            ctx['decision'] = self.payload['decision']
        if 'file_name' in self.payload:
            ctx['file_name'] = self.payload['file_name']
        if 'file_path' in self.payload:
            ctx['file_path'] = self.payload['file_path']
        return ctx

    def get_linked_objects_keys(self):
        keys = {}
        file_sha256 = self.payload.get("file_sha256")
        if file_sha256:
            keys['file'] = [("sha256", file_sha256)]
        signing_chain = self.payload.get("signing_chain")
        if not signing_chain:
            return keys
        team_id = self.payload.get("team_id")
        cert_sha256_list = []
        for cert_idx, cert in enumerate(signing_chain):
            # cert sha256
            cert_sha256 = cert.get("sha256")
            if cert_sha256:
                cert_sha256_list.append(("sha256", cert_sha256))
            # Apple Developer Team ID
            if not team_id and cert_idx == 0:
                try:
                    issuer_cn = signing_chain[cert_idx + 1]["cn"]
                except KeyError:
                    continue
                if issuer_cn != APPLE_DEV_ID_ISSUER_CN:
                    continue
                try:
                    _, team_id = parse_apple_dev_id(cert["cn"])
                except (KeyError, ValueError):
                    pass
        if team_id:
            keys["apple_team_id"] = [(team_id,)]
        if cert_sha256_list:
            keys['certificate'] = cert_sha256_list
        return keys


register_event_type(SantaEventEvent)


class SantaLogEvent(BaseEvent):
    event_type = "santa_log"
    tags = ["santa"]


register_event_type(SantaLogEvent)


class SantaRuleSetUpdateEvent(BaseEvent):
    event_type = "santa_ruleset_update"
    tags = ["santa"]

    def get_linked_objects_keys(self):
        keys = {}
        configurations = self.payload.get("configurations")
        if configurations:
            for configuration in configurations:
                keys.setdefault("santa_configuration", []).append((configuration.get("pk"),))
        ruleset = self.payload.get("ruleset")
        if ruleset:
            keys["santa_ruleset"] = [(ruleset.get("pk"),)]
        return keys


register_event_type(SantaRuleSetUpdateEvent)


class SantaRuleUpdateEvent(BaseEvent):
    event_type = "santa_rule_update"
    tags = ["santa"]

    def get_linked_objects_keys(self):
        keys = {}
        rule = self.payload.get("rule")
        if not rule:
            return keys
        configuration = rule.get("configuration")
        if configuration:
            keys["santa_configuration"] = [(configuration.get("pk"),)]
        ruleset = rule.get("ruleset")
        if ruleset:
            keys["santa_ruleset"] = [(ruleset.get("pk"),)]
        target = rule.get("target")
        if not target:
            return keys
        sha256 = target.get("sha256")
        if not sha256:
            return keys
        target_type = target.get("type")
        if target_type == Target.BINARY:
            keys["file"] = [("sha256", sha256)]
        elif target_type == Target.CERTIFICATE:
            keys["certificate"] = [("sha256", sha256)]
        elif target_type == Target.BUNDLE:
            keys["bundle"] = [("sha256", sha256)]
        return keys


register_event_type(SantaRuleUpdateEvent)


def _build_certificate_tree_from_santa_event_cert(in_d):
    out_d = {}
    for from_a, to_a, is_dt in (("cn", "common_name", False),
                                ("org", "organization", False),
                                ("ou", "organizational_unit", False),
                                ("sha256", "sha_256", False),
                                ("valid_from", "valid_from", True),
                                ("valid_until", "valid_until", True)):
        val = in_d.get(from_a)
        if is_dt:
            val = datetime.utcfromtimestamp(val)
        out_d[to_a] = val
    return out_d


def _build_siging_chain_tree_from_santa_event(event_d):
    event_signing_chain = event_d.get("signing_chain")
    if not event_signing_chain:
        return
    signing_chain = None
    current_cert = None
    for in_d in event_signing_chain:
        cert_d = _build_certificate_tree_from_santa_event_cert(in_d)
        if current_cert:
            current_cert["signed_by"] = cert_d
        else:
            signing_chain = cert_d
        current_cert = cert_d
    return signing_chain


def _build_bundle_tree_from_santa_event(event_d):
    bundle_d = {}
    for from_a, to_a in (("file_bundle_id", "bundle_id"),
                         ("file_bundle_name", "bundle_name"),
                         ("file_bundle_version", "bundle_version"),
                         ("file_bundle_version_string", "bundle_version_str")):
        val = event_d.get(from_a)
        if val:
            bundle_d[to_a] = val
    if bundle_d:
        return bundle_d


def _build_file_tree_from_santa_event(event_d):
    app_d = {
        "source": {
            "module": "zentral.contrib.santa",
            "name": "Santa events"
        }
    }
    for from_a, to_a in (("file_name", "name"),
                         ("file_path", "path"),
                         ("file_bundle_path", "bundle_path"),
                         ("file_sha256", "sha_256")):
        app_d[to_a] = event_d.get(from_a)
    for a, val in (("bundle", _build_bundle_tree_from_santa_event(event_d)),
                   ("signed_by", _build_siging_chain_tree_from_santa_event(event_d))):
        app_d[a] = val
    return app_d


def _is_allow_unknown_event(event_d):
    return event_d.get('decision') == "ALLOW_UNKNOWN"


def _is_bundle_binary_pseudo_event(event_d):
    return event_d.get('decision') == "BUNDLE_BINARY"


def _create_missing_bundles(events):
    bundle_events = {
        sha256: event_d
        for sha256, event_d in (
            (event_d.get("file_bundle_hash"), event_d)
            for event_d in events
            if not _is_bundle_binary_pseudo_event(event_d)
        )
        if sha256
    }
    if not bundle_events:
        return
    existing_sha256_set = set(
        Bundle.objects.filter(
            target__type=Target.BUNDLE,
            target__identifier__in=bundle_events.keys(),
            uploaded_at__isnull=False,  # to recover from blocked uploads
        ).values_list("target__identifier", flat=True)
    )
    unknown_file_bundle_hashes = list(set(bundle_events.keys()) - existing_sha256_set)
    for sha256 in unknown_file_bundle_hashes:
        target, _ = Target.objects.get_or_create(type=Target.BUNDLE, identifier=sha256)
        defaults = {}
        event_d = bundle_events[sha256]
        for event_attr, bundle_attr in (("file_bundle_path", "path"),
                                        ("file_bundle_executable_rel_path", "executable_rel_path"),
                                        ("file_bundle_id", "bundle_id"),
                                        ("file_bundle_name", "name"),
                                        ("file_bundle_version", "version"),
                                        ("file_bundle_version_string", "version_str"),
                                        ("file_bundle_binary_count", "binary_count")):
            val = event_d.get(event_attr)
            if val is None:
                if bundle_attr == "binary_count":
                    val = 0
                else:
                    val = ""
            defaults[bundle_attr] = val
        Bundle.objects.get_or_create(target=target, defaults=defaults)
    return unknown_file_bundle_hashes


def _create_bundle_binaries(events):
    bundle_binary_events = {}
    for event_d in events:
        if _is_bundle_binary_pseudo_event(event_d):
            bundle_sha256 = event_d.get("file_bundle_hash")
            if bundle_sha256:
                bundle_binary_events.setdefault(bundle_sha256, []).append(event_d)
    for bundle_sha256, events in bundle_binary_events.items():
        try:
            bundle = Bundle.objects.get(target__type=Target.BUNDLE, target__identifier=bundle_sha256)
        except Bundle.DoesNotExist:
            logger.error("Unknown bundle: %s", bundle_sha256)
            continue
        if bundle.uploaded_at:
            logger.info("Bundle %s already uploaded", bundle_sha256)
            continue
        binary_targets = []
        binary_count = bundle.binary_count
        for event_d in events:
            if not binary_count:
                event_binary_count = event_d.get("file_bundle_binary_count")
                if event_binary_count:
                    binary_count = event_binary_count
            binary_sha256 = event_d.get("file_sha256")
            binary_target, _ = Target.objects.get_or_create(type=Target.BINARY, identifier=binary_sha256)
            binary_targets.append(binary_target)
        bundle.binary_targets.add(*binary_targets)
        save_bundle = False
        if not bundle.binary_count and binary_count:
            bundle.binary_count = binary_count
            save_bundle = True
        if bundle.binary_count:
            binary_target_count = bundle.binary_targets.count()
            if binary_target_count > bundle.binary_count:
                logger.error("Bundle %s as wrong number of binary targets", bundle_sha256)
            elif binary_target_count == bundle.binary_count:
                bundle.uploaded_at = datetime.utcnow()
                save_bundle = True
        if save_bundle:
            bundle.save()


def _commit_files(events):
    for event_d in events:
        try:
            file_d = _build_file_tree_from_santa_event(event_d)
        except Exception:
            logger.exception("Could not build app tree from santa event")
        else:
            try:
                File.objects.commit(file_d)
            except Exception:
                logger.exception("Could not commit file")


def _post_santa_events(enrolled_machine, user_agent, ip, events):
    def get_created_at(payload):
        return datetime.utcfromtimestamp(payload['execution_time'])

    allow_unknown_shard = enrolled_machine.enrollment.configuration.allow_unknown_shard
    if allow_unknown_shard == 100:
        include_allow_unknown = True
    elif allow_unknown_shard == 0:
        include_allow_unknown = False
    else:
        include_allow_unknown = shard(
            enrolled_machine.serial_number,
            enrolled_machine.enrollment.configuration.pk
        ) <= allow_unknown_shard

    event_iterator = (
        event_d for event_d in events
        if not _is_bundle_binary_pseudo_event(event_d) and (
            include_allow_unknown or not _is_allow_unknown_event(event_d)
        )
    )

    SantaEventEvent.post_machine_request_payloads(
        enrolled_machine.serial_number, user_agent, ip,
        event_iterator, get_created_at
    )


def process_events(enrolled_machine, user_agent, ip, data):
    events = data.get("events", [])
    if not events:
        return []
    unknown_file_bundle_hashes = _create_missing_bundles(events)
    _create_bundle_binaries(events)
    _commit_files(events)
    _post_santa_events(enrolled_machine, user_agent, ip, events)
    return unknown_file_bundle_hashes


def post_preflight_event(msn, user_agent, ip, data, incident_update):
    incident_updates = []
    if incident_update is not None:
        incident_updates.append(incident_update)
    event_request = EventRequest(user_agent, ip)
    metadata = EventMetadata(incident_updates=incident_updates, request=event_request)
    event = SantaPreflightEvent(metadata, data)
    event.post()


def post_enrollment_event(msn, user_agent, ip, data, incident_updates):
    event_request = EventRequest(user_agent, ip)
    metadata = EventMetadata(incident_updates=incident_updates, request=event_request)
    event = SantaEnrollmentEvent(metadata, data)
    event.post()


def post_santa_rule_update_event(request, data):
    metadata = EventMetadata(request=EventRequest.build_from_request(request))
    event = SantaRuleUpdateEvent(metadata, data)
    event.post()


def post_santa_ruleset_update_events(request, ruleset_data, rules_data):
    event_request = EventRequest.build_from_request(request)
    ruleset_update_event_metadata = EventMetadata(request=event_request)
    ruleset_update_event = SantaRuleSetUpdateEvent(ruleset_update_event_metadata, ruleset_data)
    ruleset_update_event.post()
    for idx, rule_data in enumerate(rules_data):
        rule_update_event_metadata = EventMetadata(request=event_request,
                                                   uuid=ruleset_update_event_metadata.uuid, index=idx + 1)
        rule_update_event = SantaRuleUpdateEvent(rule_update_event_metadata, rule_data)
        rule_update_event.post()
