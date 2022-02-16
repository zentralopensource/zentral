import logging
from django.db import transaction
import yaml
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_yield_events
from zentral.core.events import event_cls_from_type
from .puppetdb_client import PuppetDBClient


logger = logging.getLogger("zentral.contrib.puppet.preprocessors")


def default_constructor(loader, tag_suffix, node):
    return loader.construct_yaml_map(node)


def get_report_created_at(report):
    return report.pop("time", None)


class ReportEventPreprocessor(object):
    routing_key = "puppet_reports"

    def __init__(self):
        self.clients = {}
        yaml.add_multi_constructor("!ruby/object:Puppet", default_constructor)

    def get_client(self, instance_d):
        key = instance_d["puppetdb_url"]
        client = self.clients.get(key)
        if not client:
            client = PuppetDBClient(instance_d)
            self.clients[key] = client
        return client

    def update_machine(self, machine_d):
        logger.info("Update machine %s %s", machine_d["source"], machine_d["reference"])
        with transaction.atomic():
            yield from commit_machine_snapshot_and_yield_events(machine_d)

    def process_raw_event(self, raw_event):
        instance_d = raw_event["puppet_instance"]
        client = self.get_client(instance_d)

        event_type = raw_event["event_type"]

        try:
            puppet_report = yaml.load(raw_event["puppet_report"])
        except Exception:
            logger.exception("Could not read puppet report")
            return

        certname = puppet_report["host"]
        try:
            machine_d = client.get_machine_d(certname)
        except Exception:
            logger.exception("Could not get machine_d. %s %s",
                             client.get_source_d(), certname)
            return
        serial_number = machine_d["serial_number"]

        yield from self.update_machine(machine_d)

        # yield puppet event

        puppet_report.pop("logs")
        puppet_report.pop("metrics")
        puppet_report.pop("resource_statuses")

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
