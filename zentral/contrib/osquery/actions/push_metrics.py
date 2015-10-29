import logging
from zentral.core.actions.backends.base import BaseAction
from zentral.core.metric_services import metric_services

logger = logging.getLogger('zentral.contrib.osquery.actions.push_metrics')


class Action(BaseAction):
    def trigger(self, event, action_config_d):
        serial_number = event.metadata.machine_serial_number
        payload = event.payload
        metrics = []
        base_labels = [('instance', serial_number)]
        for attr, metric_cfg_d in action_config_d['metrics'].items():
            gauges = {}
            tuples = payload.get(payload['name'], None)
            if tuples is None:
                logger.error('Empty osquery result %s', event.metadata.uuid)
                continue
            for tuple_d in tuples.values():
                labels = list(base_labels)
                labels.extend([(l, tuple_d[l]) for l in event.query['key']])
                key = frozenset(labels)
                gauges[key] = float(tuple_d[attr])
            if gauges:
                metrics.append({'name': metric_cfg_d['name'],
                                'help_text': metric_cfg_d['help_text'],
                                'gauges': gauges})
        if metrics:
            for ms in metric_services.values():
                job_name = action_config_d['job_name']
                ms.push_metrics(job_name, metrics, grouping_key={'instance': serial_number})
