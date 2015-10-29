from importlib import import_module
from zentral.conf import settings

__all__ = ['metric_services']


def get_metric_service_class(module_path):
    class_name = "MetricService"
    module = import_module(module_path)
    return getattr(module, class_name)


def get_metric_services(settings):
    metric_services = {}
    for metric_service_name, metric_service_conf in settings['metric_services'].items():
        metric_service_conf = metric_service_conf.copy()
        metric_service_conf['metric_service_name'] = metric_service_name
        metric_service_class = get_metric_service_class(metric_service_conf.pop('backend'))
        metric_services[metric_service_name] = metric_service_class(metric_service_conf)
    return metric_services

metric_services = get_metric_services(settings)
