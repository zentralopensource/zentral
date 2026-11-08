import logging
import geoip2.database
from . import event_from_event_d
from .base import linked_objects_key
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.core.probes.conf import all_probes
from zentral.core.incidents.utils import apply_incident_updates


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


META_BUSINESS_UNIT_KEY = linked_objects_key(MetaBusinessUnit)


def add_meta_business_units(event):
    machine = event.metadata.machine
    if not machine:
        return
    mbu_ids = sorted(mbu["id"] for mbu in machine.cached_serialized_info_for_event.get("meta_business_units", []))
    if mbu_ids:
        event.metadata.add_objects({META_BUSINESS_UNIT_KEY: [(mbu_id,) for mbu_id in mbu_ids]})


def enrich_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)

    # ip address geolocalization
    if event.metadata.request and event.metadata.request.ip and not event.metadata.request.geo and city_db_reader:
        city = get_city(event.metadata.request.ip)
        if city:
            event.metadata.request.set_geo_from_city(city)

    # before the probe matching: the probes and the stores must see the same linked objects
    add_meta_business_units(event)

    # probe matching
    for probe in all_probes.event_filtered(event):
        event.metadata.add_probe(probe)

    # incident status updates
    for incident_event in apply_incident_updates(event):
        # the incident events get the linked objects of the original event class, not its metadata
        add_meta_business_units(incident_event)
        for probe in all_probes.event_filtered(incident_event):
            incident_event.metadata.add_probe(probe, with_incident_updates=False)
        yield incident_event

    yield event


def process_event(event):
    if isinstance(event, dict):
        event = event_from_event_d(event)
    for probe in event.metadata.iter_loaded_probes():
        for action in probe.loaded_actions:
            try:
                action.trigger(event, probe)
            except Exception:
                logger.exception("Could not trigger action %s", action)
