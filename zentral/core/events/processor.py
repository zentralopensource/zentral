import logging
from prometheus_client import start_http_server, Counter
from zentral.core.probes.conf import all_probes

logger = logging.getLogger('zentral.core.events.processor')


class EventProcessor(object):
    def __init__(self, worker_id=0, prometheus_server_base_port=None):
        self.counter = Counter('zentral_events_processed',
                               'zentral events processed',
                               ['type', 'machine_serial_number',
                                'user_agent', 'ip',
                                'processed', 'error'])
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
                        'processed': 'N',
                        'error': 'N',
                        }
        request = metadata.request
        if request:
            counter_dict['user_agent'] = request.user_agent
            counter_dict['ip'] = request.ip
        for probe in all_probes.event_filtered(event):
            counter_dict['processed'] = 'Y'
            for action, action_config_d in probe.actions:
                try:
                    action.trigger(event, probe, action_config_d)
                except:
                    logger.exception("Could not trigger action %s", action.name)
                    counter_dict['error'] = 'Y'
        self.counter.labels(**counter_dict).inc()
