import logging
from zentral.core.exceptions import ImproperlyConfigured

logger = logging.getLogger('zentral.core.probes')


probe_classes = {}


def register_probe_class(probe_cls):
    probe_model = probe_cls.get_model()
    if probe_model in probe_classes:
        raise ImproperlyConfigured("Probe class '{}' already registered".format(probe_cls))
    logger.debug('Probe class "%s" registered', probe_cls)
    probe_classes[probe_model] = probe_cls
