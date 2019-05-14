from datetime import datetime
import logging
from zentral.core.events.base import BaseEvent, register_event_type
from zentral.contrib.santa.models import CollectedApplication

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


def build_certificate_tree_from_santa_event_cert(in_d):
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


def build_siging_chain_tree_from_santa_event(event_d):
    event_signing_chain = event_d.get("signing_chain")
    if not event_signing_chain:
        return
    signing_chain = None
    current_cert = None
    for in_d in event_signing_chain:
        cert_d = build_certificate_tree_from_santa_event_cert(in_d)
        if current_cert:
            current_cert["signed_by"] = cert_d
        else:
            signing_chain = cert_d
        current_cert = cert_d
    return signing_chain


def build_bundle_tree_from_santa_event(event_d):
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


def build_collected_app_tree_from_santa_event(event_d):
    app_d = {}
    for from_a, to_a in (("file_name", "name"),
                         ("file_path", "path"),
                         ("file_bundle_path", "bundle_path"),
                         ("file_sha256", "sha_256")):
        app_d[to_a] = event_d.get(from_a)
    for a, val in (("bundle", build_bundle_tree_from_santa_event(event_d)),
                   ("signed_by", build_siging_chain_tree_from_santa_event(event_d))):
        app_d[a] = val
    return app_d


def get_created_at(payload):
    return datetime.utcfromtimestamp(payload['execution_time'])


def post_events(msn, user_agent, ip, data):
    events = data.get("events", [])
    for event_d in events:
        try:
            app_d = build_collected_app_tree_from_santa_event(event_d)
        except Exception:
            logger.exception("Could not build app tree from santa event")
        else:
            try:
                CollectedApplication.objects.commit(app_d)
            except Exception:
                logger.exception("Could not commit collected appi %s", app_d)
    SantaEventEvent.post_machine_request_payloads(msn, user_agent, ip,
                                                  data.get('events', []),
                                                  get_created_at)


def post_preflight_event(msn, user_agent, ip, data):
    SantaPreflightEvent.post_machine_request_payloads(msn, user_agent, ip, [data])


def post_enrollment_event(msn, user_agent, ip, data):
    SantaEnrollmentEvent.post_machine_request_payloads(msn, user_agent, ip, [data])
