import hashlib
import json
import redis


class EventQueues(object):
    def __init__(self, config_d):
        self._r = redis.Redis(host=config_d.get('host', 'localhost'),
                              port=config_d.get('port', 6379),
                              db=config_d.get('db', 0))
        self.stores = config_d['stores']

    @staticmethod
    def _store_job_queue(store):
        return "%s_store_job_q" % store

    @staticmethod
    def _store_worker_queue(store, worker_id):
        return '%s_store_worker_%s_q' % (store, worker_id)

    @staticmethod
    def _processor_job_queue():
        return "processor_job_q"

    @staticmethod
    def _processor_worker_queue(worker_id):
        return 'processor_worker_%s_q' % worker_id

    def _get_job(self, job_q, worker_q):
        from zentral.core.events import event_from_event_d
        event_id = self._r.brpoplpush(job_q, worker_q)
        event_payload = self._r.get(event_id)
        return event_id, event_from_event_d(json.loads(event_payload.decode('utf-8')))

    def _ack_job(self, worker_q, event_id):
        event_job_counter = '%s_job_num' % event_id
        p = self._r.pipeline()
        p.lrem(worker_q, event_id)
        p.decr(event_job_counter)
        return int(p.execute()[-1])

    def _process_event(self, event_id):
        event_job_counter = '%s_job_num' % event_id
        p = self._r.pipeline()
        p.lpush(self._processor_job_queue(), event_id)
        p.incr(event_job_counter)
        p.execute()

    def _delete_event(self, event_id):
        event_job_counter = '%s_job_num' % event_id
        p = self._r.pipeline()
        p.delete(event_job_counter)
        p.delete(event_id)
        p.execute()

    def post_event(self, event):
        event_payload = json.dumps(event.serialize()).encode('utf-8')
        s = hashlib.sha1(event_payload)
        event_id = s.hexdigest().encode('utf-8')
        event_job_counter = '%s_job_num' % event_id
        p = self._r.pipeline()
        p.set(event_id, event_payload)
        p.set(event_job_counter, 0)
        for store in self.stores:
            p.lpush(self._store_job_queue(store),
                    event_id)
            p.incr(event_job_counter)
        p.execute()
        return event_id

    def get_store_event_job(self, store, worker_id):
        job_q = self._store_job_queue(store)
        worker_q = self._store_worker_queue(store, worker_id)
        return self._get_job(job_q, worker_q)

    def ack_store_event_job(self, store, worker_id, event_id):
        worker_q = self._store_worker_queue(store, worker_id)
        event_job_num = self._ack_job(worker_q, event_id)
        if event_job_num <= 0:
            self._process_event(event_id)

    def get_process_event_job(self, worker_id):
        job_q = self._processor_job_queue()
        worker_q = self._processor_worker_queue(worker_id)
        return self._get_job(job_q, worker_q)

    def ack_process_event_job(self, worker_id, event_id):
        worker_q = self._processor_worker_queue(worker_id)
        event_job_num = self._ack_job(worker_q, event_id)
        if event_job_num <= 0:
            self._delete_event(event_id)
