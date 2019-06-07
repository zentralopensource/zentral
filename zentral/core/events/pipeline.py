import logging
import geoip2.database
from . import event_from_event_d
from zentral.conf import settings
from zentral.core.probes.conf import all_probes
from zentral.core.incidents.events import build_incident_events
from zentral.core.incidents.utils import update_or_create_open_incident, update_or_create_open_machine_incident

logger = logging.getLogger('zentral.core.events.pipeline')


city_db_reader = None
try:
    city_db_path = settings["events"]["geoip2_city_db"]
except KeyError:
    pass
else:
    try:
        city_db_reader = geoip2.database.Reader(city_db_path)
    except Exception:
        logger.info("Could not open Geolite2 city database")


def get_city(ip):
    try:
        return city_db_reader.city(ip)
    except Exception:
        pass


def enrich_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)
    if event.metadata.request and event.metadata.request.ip and not event.metadata.request.geo and city_db_reader:
        city = get_city(event.metadata.request.ip)
        if city:
            event.metadata.request.set_geo_from_city(city)
    for probe in all_probes.event_filtered(event):
        incident_severity = probe.get_matching_event_incident_severity(event)
        if incident_severity is None:
            continue
        if event.metadata.machine_serial_number is not None:
            machine_incident, incident_event_payloads = update_or_create_open_machine_incident(
                probe.source,
                incident_severity,
                event.metadata.machine_serial_number,
                event.metadata.uuid
            )
            event.metadata.add_incident(machine_incident)
        else:
            incident, incident_event_payloads = update_or_create_open_incident(
                probe.source,
                incident_severity,
                event.metadata.uuid
            )
            event.metadata.add_incident(incident)

        yield from build_incident_events(incident_event_payloads,
                                         event.metadata.machine_serial_number,  # copied from original event
                                         event.metadata.request)  # copied from original event
    yield event


def process_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)
    for probe in all_probes.event_filtered(event):
        for action, action_config_d in probe.actions:
            try:
                action.trigger(event, probe, action_config_d)
            except Exception:
                logger.exception("Could not trigger action %s", action.name)
