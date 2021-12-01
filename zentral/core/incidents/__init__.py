import logging
from zentral.core.exceptions import ImproperlyConfigured


default_app_config = "zentral.core.incidents.apps.ZentralIncidentsAppConfig"


logger = logging.getLogger("zentral.core.incidents")


# incident types


incident_types = {}


def register_incident_class(incident_cls):
    incident_type = incident_cls.incident_type
    if incident_type in incident_types:
        raise ImproperlyConfigured(f'Incident type {incident_type} already registered')
    logger.debug('Incident type "%s" registered', incident_type)
    incident_types[incident_type] = incident_cls


def incident_cls_from_type(incident_type):
    try:
        return incident_types[incident_type]
    except KeyError:
        logger.error('Unknown incident type "%s"', incident_type)
        # BaseIncident registered in .incidents
        return incident_types["base"]
