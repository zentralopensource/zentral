__all__ = ['BaseMetricService']


class BaseMetricService(object):
    def __init__(self, config_d):
        self.config_d = config_d
        self.name = self.config_d['metric_service_name']
