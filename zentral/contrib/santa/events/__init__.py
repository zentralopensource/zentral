from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, register_event_type
from zentral.contrib.inventory.models import File
from zentral.contrib.santa.models import Bundle, Target


logger = logging.getLogger('zentral.contrib.santa.events')


ALL_EVENTS_SEARCH_DICT = {"tag": "santa"}


class SantaEnrollmentEvent(BaseEvent):
    event_type = "santa_enrollment"
    tags = ["santa"]


register_event_type(SantaEnrollmentEvent)


class SantaPreflightEvent(BaseEvent):
    event_type = "santa_preflight"
    tags = ["santa", "heartbeat"]
    heartbeat_timeout = 2 * 10 * 60


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


register_event_type(SantaEventEvent)


class SantaLogEvent(BaseEvent):
    event_type = "santa_log"
    tags = ["santa"]


register_event_type(SantaLogEvent)


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
            target__sha256__in=bundle_events.keys(),
            uploaded_at__isnull=False,  # to recover from blocked uploads
        ).values_list("target__sha256", flat=True)
    )
    unknown_file_bundle_hashes = list(set(bundle_events.keys()) - existing_sha256_set)
    for sha256 in unknown_file_bundle_hashes:
        target, _ = Target.objects.get_or_create(type=Target.BUNDLE, sha256=sha256)
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
            bundle = Bundle.objects.get(target__type=Target.BUNDLE, target__sha256=bundle_sha256)
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
            binary_target, _ = Target.objects.get_or_create(type=Target.BINARY, sha256=binary_sha256)
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

    SantaEventEvent.post_machine_request_payloads(
        enrolled_machine.serial_number, user_agent, ip,
        (event_d for event_d in events if not _is_bundle_binary_pseudo_event(event_d)),
        get_created_at
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


def post_preflight_event(msn, user_agent, ip, data):
    SantaPreflightEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_enrollment_event(msn, user_agent, ip, data):
    SantaEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
