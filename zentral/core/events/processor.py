import logging
from prometheus_client import start_http_server, Counter
from zentral.core.actions import actions

logger = logging.getLogger('zentral.core.events.processor')


class EventProcessor(object):
    def __init__(self, worker_id=0, prometheus_server_base_port=None):
        self.counter = Counter('zentral_events_processed',
                               'zentral events processed',
                               ['type', 'machine_serial_number',
                                'user_agent', 'ip',
                                'probe', 'query',
                                'processed', 'filtered_out'])
        self.worker_id = worker_id
        self.prometheus_server_base_port = prometheus_server_base_port
        self._start_prometheus_server()

    def _start_prometheus_server(self):
        if not self.prometheus_server_base_port:
            logger.error("Can't start prometheus server: missing prometheus_server_base_port configuration")
            return
        server_port = int(self.prometheus_server_base_port) + self.worker_id
        start_http_server(server_port)
        logger.info('Prometheus server started on port %s', server_port)

    def process(self, event):
        metadata = event.metadata
        counter_dict = {'type': event.event_type,
                        'machine_serial_number': metadata.machine_serial_number,
                        'user_agent': '_',
                        'ip': '_',
                        'probe': '_',
                        'query': '_',
                        'processed': 'N',
                        'filtered_out': 'N'}
        request = metadata.request
        if request:
            counter_dict['user_agent'] = request.user_agent
            counter_dict['ip'] = request.ip
        if hasattr(event, 'probe') and event.probe:
            counter_dict['probe'] = event.probe['name']
            if hasattr(event, 'query') and event.query:
                counter_dict['query'] = event.query['name']
        else:
            self.counter.labels(counter_dict).inc()
            return
        if event.is_filtered_out():
            counter_dict['filtered_out'] = 'Y'
            self.counter.labels(counter_dict).inc()
            return
        counter_dict['processed'] = 'Y'
        self.counter.labels(counter_dict).inc()
        for action_name, action_config_d in event.probe['actions'].items():
            try:
                action = actions[action_name]
            except KeyError:
                logger.error('Unknown action %s', action_name)
                continue
            try:
                action.trigger(event, action_config_d)
            except:
                logger.exception("Could not trigger action %s", action_name)
