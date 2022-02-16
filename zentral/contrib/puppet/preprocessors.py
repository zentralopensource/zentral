import logging
from dateutil import parser
from django.db import transaction
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_yield_events
from zentral.core.events import event_cls_from_type
from .conf import puppet_conf
from .puppetdb_client import PuppetDBClient


logger = logging.getLogger("zentral.contrib.puppet.preprocessors")


def default_constructor(loader, tag_suffix, node):
    return loader.construct_yaml_map(node)


def get_report_created_at(report):
    try:
        return parser.parse(report["time"])
    except (KeyError, ValueError, TypeError):
        pass


class ReportEventPreprocessor(object):
    routing_key = "puppet_reports"

    def __init__(self):
        self.clients = {}

    def get_client(self, puppetdb_url):
        client = self.clients.get(puppetdb_url)
        if not client:
            instance = puppet_conf.instances[puppetdb_url]
            client = PuppetDBClient(instance)
            self.clients[puppetdb_url] = client
        return client

    def update_machine(self, machine_d):
        logger.info("Update machine %s %s", machine_d["source"], machine_d["reference"])
        with transaction.atomic():
            yield from commit_machine_snapshot_and_yield_events(machine_d)

    def process_raw_event(self, raw_event):
        puppetdb_url = raw_event["puppetdb_url"]
        client = self.get_client(puppetdb_url)

        event_type = raw_event["event_type"]

        puppet_report = raw_event["puppet_report"]
        try:
            certname = puppet_report["host"]
        except (TypeError, KeyError):
            logger.exception("Could not get host from puppet report")
            return

        try:
            machine_d = client.get_machine_d(certname)
        except Exception:
            logger.exception("Could not get machine_d. %s %s",
                             client.get_source_d(), certname)
            return
        serial_number = machine_d["serial_number"]

        yield from self.update_machine(machine_d)

        # yield puppet event

        event_cls = event_cls_from_type(event_type)
        yield from event_cls.build_from_machine_request_payloads(
            serial_number,
            raw_event["request"]["user_agent"],
            raw_event["request"]["ip"],
            [puppet_report],
            get_created_at=get_report_created_at
        )


def get_preprocessors():
    yield ReportEventPreprocessor()
