import os
import sys
ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, ROOT_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()
from multiprocessing import Process
from zentral.conf import settings
from zentral.core.events.processor import EventProcessor
from zentral.core.queues import queues


def process_events(worker_id, prometheus_server_base_port):
    event_processor = EventProcessor(worker_id,
                                     prometheus_server_base_port)
    processor_worker = queues.get_processor_worker(event_processor)
    processor_worker.run()

if __name__ == '__main__':
    pw_settings = settings.get('processor_workers', {})
    worker_num = int(pw_settings.get('number', 1))
    prometheus_server_base_port = pw_settings.get('prometheus_server_base_port', None)
    p_l = []
    for worker_id in range(worker_num):
        p = Process(target=process_events,
                    args=(worker_id, prometheus_server_base_port))
        p.daemon = 1
        p.start()
        p_l.append(p)
    for p in p_l:
        p.join()
