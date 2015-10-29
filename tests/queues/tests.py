import json
import unittest
import redis
from zentral.core.events import EventMetadata, EventRequest, BaseEvent, register_event_type
from zentral.core.queues.backends.redisq import EventQueues


class TestEvent1(BaseEvent):
    event_type = "event_type_1"

register_event_type(TestEvent1)


class TestEventQueues(unittest.TestCase):
    CONFIG = {'db': 1,
              'stores': ['postgres']}
    EVENT = TestEvent1(EventMetadata(TestEvent1.event_type,
                                     machine_serial_number='012356789',
                                     request=EventRequest("python_unittest_useragent",
                                                          "10.0.0.1")),
                       {'payload': 'ok'})

    def setUp(self):
        self.r = redis.Redis(host='localhost', port=6379, db=self.CONFIG['db'])
        self.rq = EventQueues(self.CONFIG)

    def test_post_event(self):
        event_id = self.rq.post_event(self.EVENT)

        self.assertEqual(json.loads(self.r.get(event_id).decode('utf-8')), self.EVENT.serialize())
        self.assertEqual(int(self.r.get('%s_job_num' % event_id)), 1)
        job_q = self.rq._store_job_queue('postgres')
        self.assertEqual(self.r.llen(job_q), 1)
        self.assertEqual(self.r.rpop(job_q), event_id)

    def test_get_store_event_job(self):
        event_id = self.rq.post_event(self.EVENT)
        job_t = self.rq.get_store_event_job('postgres', 0)

        self.assertEqual(job_t, (event_id, self.EVENT))
        job_q = self.rq._store_job_queue('postgres')
        self.assertEqual(self.r.llen(job_q), 0)
        worker_q = self.rq._store_worker_queue('postgres', 0)
        self.assertEqual(self.r.llen(worker_q), 1)
        self.assertEqual(self.r.rpop(worker_q), event_id)

    def test_ack_store_event_job(self):
        event_id = self.rq.post_event(self.EVENT)
        j_event_id, j_event = self.rq.get_store_event_job('postgres', 0)
        self.rq.ack_store_event_job('postgres', 0, j_event_id)

        worker_q = self.rq._store_worker_queue('postgres', 0)
        self.assertEqual(self.r.llen(worker_q), 0)
        event_job_counter = '%s_job_num' % event_id
        self.assertEqual(int(self.r.get(event_job_counter)), 1)
        job_q = self.rq._processor_job_queue()
        self.assertEqual(self.r.llen(job_q), 1)
        self.assertEqual(self.r.rpop(job_q), event_id)

    def test_get_process_event_job(self):
        event_id = self.rq.post_event(self.EVENT)
        j_event_id, j_event = self.rq.get_store_event_job('postgres', 0)
        self.rq.ack_store_event_job('postgres', 0, j_event_id)
        job_t = self.rq.get_process_event_job(0)

        self.assertEqual(job_t, (event_id, self.EVENT))
        job_q = self.rq._processor_job_queue()
        self.assertEqual(self.r.llen(job_q), 0)
        worker_q = self.rq._processor_worker_queue(0)
        self.assertEqual(self.r.llen(worker_q), 1)
        self.assertEqual(self.r.rpop(worker_q), event_id)

    def test_ack_process_event_job(self):
        event_id = self.rq.post_event(self.EVENT)
        j_event_id, j_event = self.rq.get_store_event_job('postgres', 0)
        self.rq.ack_store_event_job('postgres', 0, j_event_id)
        j_event_id, j_event = self.rq.get_process_event_job(0)
        self.rq.ack_process_event_job(0, j_event_id)

        worker_q = self.rq._processor_worker_queue(0)
        self.assertEqual(self.r.llen(worker_q), 0)
        self.assertEqual(self.r.get(event_id), None)
        event_job_counter = '%s_job_num' % event_id
        self.assertEqual(self.r.get(event_job_counter), None)

    def tearDown(self):
        self.r.flushdb()


if __name__ == '__main__':
    unittest.main()
