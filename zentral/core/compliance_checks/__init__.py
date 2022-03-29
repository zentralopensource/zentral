import logging
from zentral.core.exceptions import ImproperlyConfigured


logger = logging.getLogger("zentral.core.compliance_checks")


# compliance checks classes


compliance_check_classes = {}


def register_compliance_check_class(compliance_check_class):
    try:
        model = compliance_check_class.get_model()
    except AttributeError:
        raise ImproperlyConfigured('Not a valid compliance check class')
    if model in compliance_check_classes:
        raise ImproperlyConfigured(f'Compliance check class "{model}" already registered')
    compliance_check_classes[model] = compliance_check_class
    logger.debug('Compliance check class "%s" registered', model)


def compliance_check_class_from_model(model):
    try:
        return compliance_check_classes[model]
    except KeyError:
        logger.error('Unknown compliance check model "%s"', model)
        # BaseComplianceCheck registered in .compliance_checks
        return compliance_check_classes["BaseComplianceCheck"]
