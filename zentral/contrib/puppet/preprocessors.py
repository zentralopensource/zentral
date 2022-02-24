import logging
from dateutil import parser
from django.db import transaction
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_yield_events
from .events import PuppetReportEvent
from .models import Instance
from .puppetdb_client import PuppetDBClient


logger = logging.getLogger("zentral.contrib.puppet.preprocessors")


def get_report_created_at(report):
    try:
        return parser.parse(report["time"])
    except (KeyError, ValueError, TypeError):
        pass


class ReportEventPreprocessor(object):
    routing_key = "puppet_reports"

    def __init__(self):
        self.clients = {}

    def get_client(self, instance_d):
        client = None
        instance_pk = instance_d["pk"]
        instance_version = instance_d["version"]
        try:
            client, client_instance_version = self.clients[instance_pk]
        except KeyError:
            pass
        else:
            if client_instance_version < instance_version:
                client = None
        if client is None:
            try:
                instance = Instance.objects.get(pk=instance_pk)
            except Instance.DoesNotExist:
                logger.error("Instance %s not found", instance_pk)
                return
            client = PuppetDBClient.from_instance(instance)
            self.clients[instance_pk] = (client, instance.version)
        return client

    def update_machine(self, machine_d):
        logger.info("Update machine %s %s", machine_d["source"], machine_d["reference"])
        with transaction.atomic():
            yield from commit_machine_snapshot_and_yield_events(machine_d)

    def process_raw_event(self, raw_event):
        # client
        instance_d = raw_event.get("puppet_instance")
        if not instance_d:
            # TODO legacy raw event format → remove
            logger.error("Puppet instance not found in raw event")
            return
        client = self.get_client(instance_d)
        if client is None:
            return

        puppet_report = raw_event["puppet_report"]

        # machine
        try:
            certname = puppet_report["host"]
        except (TypeError, KeyError):
            logger.exception("Could not get host from puppet report")
            return
        try:
            machine_d = client.get_machine_d(certname)
        except Exception:
            logger.exception("Could not get machine_d: %s %s", client.get_source_d(), certname)
            return

        # inventory update events
        yield from self.update_machine(machine_d)

        # puppet report event
        yield from PuppetReportEvent.build_from_machine_request_payloads(
            machine_d["serial_number"],
            raw_event["request"]["user_agent"],
            raw_event["request"]["ip"],
            [puppet_report],
            get_created_at=get_report_created_at,
            observer=raw_event.get("observer")
        )


def get_preprocessors():
    yield ReportEventPreprocessor()
