from datetime import datetime
import json
import os.path
import queue
from unittest.mock import Mock, patch
import boto3
from botocore.stub import Stubber
from django.test import TestCase
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from pyarrow.fs import LocalFileSystem
from zentral.conf.config import ConfigDict
from zentral.core.queues.backends.aws_sns_sqs import (BulkStoreWorker, ConcurrentStoreWorker, EnrichWorker,
                                                      EventQueues, PreprocessWorker, ProcessWorker, SimpleStoreWorker)
from zentral.core.stores.backends.http import HTTPStoreSerializer
from zentral.core.stores.backends.s3_parquet import S3ParquetStoreSerializer
from zentral.core.stores.models import Store


class AWSSNSSQSQueuesTestCase(TestCase):
    maxDiff = None

    @staticmethod
    def build_store(name=None, event_filters=None, provisioned=False, backend="HTTP", backend_kwargs=None):
        if event_filters is None:
            event_filters = {}
        if backend_kwargs is None:
            backend_kwargs = {"endpoint_url": "https://www.example.com",
                              "concurrency": 1}
        name = name or get_random_string(12)
        store = Store.objects.create(
            name=name,
            slug=slugify(name),
            event_filters=event_filters,
            backend=backend,
            backend_kwargs={},
        )
        store.set_backend_kwargs(backend_kwargs)
        if provisioned:
            store.provisioning_uid = get_random_string(12)
        store.save()
        return store.get_backend(load=True)

    @staticmethod
    def get_queues(config=None):
        if config is None:
            config = ConfigDict({
                "prefix": "prefix-",
                "tags": {"un": "1"},
                "region_name": "eu-central-1",
                "aws_access_key_id": "aaki",  # do not wait for default credentials!
                "aws_secret_access_key": "asak",
                "predefined_queues": {
                    "store-enriched-events-opensearch": "https://www.example.com/yolo"
                },
                "predefined_topics": {
                    "enriched-events": "arn:yolo"
                }
            })
        return EventQueues(config)

    def test_create_event_queues_defaults(self):
        eq = self.get_queues({})
        self.assertEqual(eq._prefix, "ztl-")
        self.assertEqual(eq._tags, {"Product": "Zentral"})
        self.assertEqual(list(eq.client_kwargs.keys()), ["config"])
        self.assertEqual(eq._known_queues, {})
        self.assertEqual(eq._predefined_queue_basenames, [])
        self.assertEqual(eq._known_topics, {})

    def test_create_event_queues_more(self):
        eq = self.get_queues()
        self.assertEqual(eq._prefix, "prefix-")
        self.assertEqual(eq._tags, {"un": "1"})
        self.assertEqual(list(eq.client_kwargs.keys()),
                         ["config", "region_name", "aws_access_key_id", "aws_secret_access_key"])
        self.assertEqual(eq.client_kwargs["region_name"], "eu-central-1")
        self.assertEqual(eq.client_kwargs["aws_access_key_id"], "aaki")
        self.assertEqual(eq.client_kwargs["aws_secret_access_key"], "asak")
        self.assertEqual(eq._known_queues, {
            "store-enriched-events-opensearch": "https://www.example.com/yolo",
        })
        self.assertEqual(
            eq._predefined_queue_basenames,
            ["store-enriched-events-opensearch"]
        )
        self.assertEqual(
            eq._known_topics,
            {"enriched-events": "arn:yolo"}
        )

    def test_sns_client(self):
        eq = self.get_queues({"region_name": "eu-central-1", "aws_access_key_id": "a", "aws_secret_access_key": "b"})
        self.assertEqual(eq.sns_client.__class__.__name__, "SNS")
        self.assertEqual(eq.sns_client._client_config.region_name, "eu-central-1")

    def test_sqs_client(self):
        eq = self.get_queues({"region_name": "eu-central-1", "aws_access_key_id": "a", "aws_secret_access_key": "b"})
        self.assertEqual(eq.sqs_client.__class__.__name__, "SQS")
        self.assertEqual(eq.sqs_client._client_config.region_name, "eu-central-1")

    def test_setup_known_topic(self):
        eq = self.get_queues()
        self.assertEqual(eq.setup_topic("enriched-events"), "arn:yolo")
        self.assertEqual(eq._known_topics, {
            "enriched-events": "arn:yolo",
        })

    @patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client")
    def test_setup_topic(self, client):
        client.return_value.create_topic.return_value = {"TopicArn": "arn:fomo"}
        eq = self.get_queues()
        self.assertEqual(eq.setup_topic("yolo"), "arn:fomo")
        self.assertEqual(eq._known_topics, {
            "enriched-events": "arn:yolo",
            "yolo": "arn:fomo",
        })

    def test_get_known_queue(self):
        eq = self.get_queues()
        self.assertEqual(
            eq.get_queue("store-enriched-events-opensearch"),
            (True, "prefix-store-enriched-events-opensearch-queue", "https://www.example.com/yolo")
        )

    def test_get_existing_queue(self):
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_response(
            "get_queue_url",
            {"QueueUrl": "https://www.example.com/fomo"},
            {"QueueName": "prefix-yolo-queue"}
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.get_queue("yolo"),
                (False, "prefix-yolo-queue", "https://www.example.com/fomo")
            )
            self.assertEqual(eq._known_queues, {
                "store-enriched-events-opensearch": "https://www.example.com/yolo",
                "yolo": "https://www.example.com/fomo",
            })

    def test_get_missing_queue(self):
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_client_error("get_queue_url", service_error_code="QueueDoesNotExist")
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.get_queue("yolo"),
                (False, "prefix-yolo-queue", None)
            )
            self.assertEqual(eq._known_queues, {
                "store-enriched-events-opensearch": "https://www.example.com/yolo",
            })

    def test_get_or_create_known_queue(self):
        eq = self.get_queues()
        self.assertEqual(
            eq.get_or_create_queue("store-enriched-events-opensearch"),
            (True, "https://www.example.com/yolo", False)
        )

    def test_get_or_create_existing_queue(self):
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_response(
            "get_queue_url",
            {"QueueUrl": "https://www.example.com/fomo"},
            {"QueueName": "prefix-yolo-queue"}
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.get_or_create_queue("yolo"),
                (False, "https://www.example.com/fomo", False)
            )
            self.assertEqual(eq._known_queues, {
                "store-enriched-events-opensearch": "https://www.example.com/yolo",
                "yolo": "https://www.example.com/fomo",
            })

    def test_get_or_create_missing_queue(self):
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_client_error(
            "get_queue_url",
            service_error_code="QueueDoesNotExist"
        )
        stub.add_response(
            "create_queue",
            {"QueueUrl": "https://www.example.com/fomo"},
            {"QueueName": "prefix-yolo-queue", "tags": {"un": "1"}}
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.get_or_create_queue("yolo"),
                (False, "https://www.example.com/fomo", True)
            )
            self.assertEqual(eq._known_queues, {
                "store-enriched-events-opensearch": "https://www.example.com/yolo",
                "yolo": "https://www.example.com/fomo",
            })

    def test_get_queue_arn(self):
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_response(
            "get_queue_attributes",
            {"Attributes": {"QueueArn": "arn:fomo"}},
            {"QueueUrl": "https://www.example.com/fomo",
             "AttributeNames": ["QueueArn"]},
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.get_queue_arn("https://www.example.com/fomo"),
                "arn:fomo",
            )

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue_arn")
    def test_setup_queue_subscription(self, get_queue_arn):
        get_queue_arn.return_value = "arn:queue"
        sqs_client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        sqs_stub = Stubber(sqs_client)
        sqs_stub.add_response(
            "set_queue_attributes",
            {},
            {"QueueUrl": "https://www.example.com/fomo",
             "Attributes": {
                 "Policy": json.dumps({
                     "Version": "2012-10-17",
                     "Statement": [
                         {"Sid": "AllowSendMessageFromSNSTopic",
                          "Principal": {"Service": "sns.amazonaws.com"},
                          "Action": ["sqs:SendMessage"],
                          "Effect": "Allow",
                          "Resource": "arn:queue",
                          "Condition": {"ArnEquals": {"aws:SourceArn": "arn:yolo"}}}
                     ]
                 })
             }},
        )
        sqs_stub.activate()
        sns_client = boto3.client(
            "sns", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        sns_stub = Stubber(sns_client)
        sns_stub.add_response(
            "subscribe",
            {},
            {"TopicArn": "arn:yolo",
             "Protocol": "sqs",
             "Endpoint": "arn:queue",
             "Attributes": {"RawMessageDelivery": "true"}}
        )
        sns_stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", side_effect=[sqs_client, sns_client]):
            eq = self.get_queues()
            self.assertIsNone(eq.setup_queue_subscription("https://www.example.com/fomo", "enriched-events"))
        get_queue_arn.assert_called_once_with("https://www.example.com/fomo")

    def test_setup_predefined_queue(self):
        eq = self.get_queues()
        self.assertEqual(
            eq.setup_queue("store-enriched-events-opensearch", "enriched-events"),
            "https://www.example.com/yolo",
        )

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_or_create_queue")
    def test_setup_existing_queue_no_topic(self, get_or_create_queue):
        get_or_create_queue.return_value = (False, "https://www.example.com/fomo", False)
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_response(
            "untag_queue",
            {},
            {"QueueUrl": "https://www.example.com/fomo",
             "TagKeys": ["Zentral:ToDelete"]},
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            self.assertEqual(
                eq.setup_queue("yolo"),
                "https://www.example.com/fomo"
            )
        get_or_create_queue.assert_called_once_with("yolo")

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.setup_queue_subscription")
    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_or_create_queue")
    def test_setup_missing_queue_topic(self, get_or_create_queue, setup_queue_subscription):
        get_or_create_queue.return_value = (False, "https://www.example.com/fomo", True)
        eq = self.get_queues()
        self.assertEqual(
            eq.setup_queue("yolo", "enriched-events"),
            "https://www.example.com/fomo"
        )
        get_or_create_queue.assert_called_once_with("yolo")
        setup_queue_subscription.assert_called_once_with("https://www.example.com/fomo", "enriched-events")

    def test_get_provisioned_store_worker_queue_basename(self):
        store = self.build_store(provisioned=True)
        eq = self.get_queues()
        self.assertEqual(
            eq.get_store_worker_queue_basename(store),
            f"store-enriched-events-{store.slug}"
        )

    def test_get_store_worker_queue_basename(self):
        store = self.build_store()
        eq = self.get_queues()
        self.assertEqual(
            eq.get_store_worker_queue_basename(store),
            f"store-enriched-events-{store.instance.pk}"
        )

    def test_setup_store_worker_predefined_queue(self):
        store = self.build_store(name="OpenSearch", provisioned=True)
        eq = self.get_queues()
        self.assertEqual(
            eq.setup_store_worker_queue(store),
            "https://www.example.com/yolo"
        )

    @patch("zentral.core.queues.backends.aws_sns_sqs.logger.warning")
    def test_mark_store_worker_predefined_queue_for_deletion(self, logger_warning):
        store = self.build_store(name="OpenSearch", provisioned=True)
        eq = self.get_queues()
        eq.mark_store_worker_queue_for_deletion(store)
        logger_warning.assert_called_once_with("Predefined queue %s cannot be marked for deletion",
                                               "store-enriched-events-opensearch")

    @patch("zentral.core.queues.backends.aws_sns_sqs.logger.warning")
    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_mark_store_worker_missing_queue_for_deletion(self, get_queue, logger_warning):
        store = self.build_store(name="Elasticsearch", provisioned=True)
        get_queue.return_value = (False, "store-enriched-events-elasticsearch-queue", None)
        eq = self.get_queues()
        eq.mark_store_worker_queue_for_deletion(store)
        logger_warning.assert_called_once_with("Missing queue %s cannot be marked for deletion",
                                               "store-enriched-events-elasticsearch-queue")
        get_queue.assert_called_once_with("store-enriched-events-elasticsearch")

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    @patch("zentral.core.queues.backends.aws_sns_sqs.datetime")
    def test_mark_store_worker_queue_for_deletion(self, patched_datetime, get_queue):
        patched_datetime.utcnow.return_value = datetime(2000, 1, 1)
        store = self.build_store(name="Elasticsearch", provisioned=True)
        get_queue.return_value = (
            False,
            "store-enriched-events-elasticsearch-queue",
            "https://www.example.com/fomo",
        )
        client = boto3.client(
            "sqs", region_name="eu-central-1",
            aws_access_key_id="a", aws_secret_access_key="b"
        )
        stub = Stubber(client)
        stub.add_response(
            "tag_queue",
            {},
            {"QueueUrl": "https://www.example.com/fomo",
             "Tags": {"Zentral:ToDelete": "2000-01-01T00:00:00"}},
        )
        stub.activate()
        with patch("zentral.core.queues.backends.aws_sns_sqs.boto3.client", return_value=client):
            eq = self.get_queues()
            eq.mark_store_worker_queue_for_deletion(store)
        get_queue.assert_called_once_with("store-enriched-events-elasticsearch")

    # workers

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_get_preprocess_worker(self, get_queue):
        get_queue.return_value = (True, "raw-events", "https://www.example.com/fomo")
        eq = self.get_queues()
        w = eq.get_preprocess_worker()
        self.assertIsInstance(w, PreprocessWorker)
        self.assertEqual(w._threads[0].visibility_timeout, 120)

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_get_enrich_worker(self, get_queue):
        get_queue.return_value = (True, "events", "https://www.example.com/fomo")
        eq = self.get_queues()
        w = eq.get_enrich_worker(lambda e: e)
        self.assertIsInstance(w, EnrichWorker)
        self.assertEqual(w._threads[0].visibility_timeout, 120)

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_get_process_worker(self, get_queue):
        get_queue.return_value = (True, "process-enriched-events", "https://www.example.com/fomo")
        eq = self.get_queues()
        w = eq.get_process_worker(lambda e: e)
        self.assertIsInstance(w, ProcessWorker)
        self.assertEqual(w._threads[0].visibility_timeout, 120)

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    @patch("zentral.core.stores.backends.s3_parquet.S3ParquetStore._get_filesystem")
    def test_get_bulk_store_worker(self, get_fs, get_queue):
        get_fs.return_value = LocalFileSystem()
        get_queue.return_value = (True, "store-worker-s3-parquet", "https://www.example.com/fomo")
        prefix = get_random_string(12) + "/"
        store = self.build_store(
            name="S3 Parquet", provisioned=True,
            backend="S3_PARQUET",
            backend_kwargs=S3ParquetStoreSerializer({
                "bucket": "/tmp",
                "prefix": prefix,
                "region_name": "eu-central-1"
            }).data,
        )
        store.wait_and_configure_if_necessary()
        store._fs.create_dir(os.path.dirname(store._get_parquet_path()))
        self.assertTrue(store.batch_size > 1)
        eq = self.get_queues()
        w = eq.get_store_worker(store)
        self.assertIsInstance(w, BulkStoreWorker)
        self.assertEqual(w.max_batch_age_seconds, 300)
        self.assertFalse(w._batch_is_big_enough())
        self.assertFalse(w._batch_is_too_old())
        self.assertEqual(w._threads[0].visibility_timeout, 480)

        # process one message in the queue if in queue empty
        # and stop_receiving_event is set
        w.process_message_queue.get = Mock(side_effect=queue.Empty)
        w.stop_receiving_event.is_set = Mock(return_value=True)
        w.batch.append(
            ("receipt_handle_0", "routing_key",
             {"_zentral": {
                 "id": "00000000-0000-0000-0000-000000000000",
                 "index": 1,
                 "type": "event_type",
                 "created_at": "2026-01-01",
              }})
        )
        w.setup_metrics_exporter()
        w.start_run_loop()
        w.process_message_queue.get.assert_called_once()
        self.assertEqual(w.delete_message_queue.get()[0], "receipt_handle_0")
        self.assertEqual(len(w.batch), 0)
        self.assertIsNone(w.batch_start_ts)

        # process one message in the queue if in queue empty
        # and batch is too old
        w.process_message_queue.get = Mock(side_effect=queue.Empty)
        w.stop_receiving_event.is_set = Mock(side_effect=[False, True])
        w.batch.append(
            ("receipt_handle_1", "routing_key",
             {"_zentral": {
                 "id": "00000000-0000-0000-0000-000000000001",
                 "index": 1,
                 "type": "event_type",
                 "created_at": "2026-01-01",
              }})
        )
        w.batch_start_ts = -1000
        w.max_batch_age_seconds = 0
        w.start_run_loop()
        self.assertEqual(w.delete_message_queue.get()[0], "receipt_handle_1")
        self.assertEqual(len(w.batch), 0)
        self.assertIsNone(w.batch_start_ts)

        # process one message in the queue if in queue empty
        # and batch is too old
        w.stop_receiving_event.is_set = Mock(return_value=True)
        w.process_message_queue.get = Mock(side_effect=[
            ("receipt_handle_2", "routing_key",
             {"_zentral": {
                 "id": "00000000-0000-0000-0000-000000000002",
                 "index": 1,
                 "type": "event_type",
                 "created_at": "2026-01-01",
              }}),
            queue.Empty,
        ])
        w.max_batch_age_seconds = 0
        w.start_run_loop()
        self.assertEqual(w.delete_message_queue.get()[0], "receipt_handle_2")
        self.assertEqual(len(w.batch), 0)
        self.assertIsNone(w.batch_start_ts)

        # skip message
        w.skip_event = Mock(return_value=True)
        w.process_message_queue.get = Mock(side_effect=[
            ("receipt_handle_3", "routing_key",
             {"_zentral": {
                 "id": "00000000-0000-0000-0000-000000000003",
                 "index": 1,
                 "type": "event_type",
                 "created_at": "2026-01-01",
              }}),
            queue.Empty,
        ])
        w.start_run_loop()
        w.skip_event.assert_called_once()
        self.assertEqual(w.delete_message_queue.get()[0], "receipt_handle_3")
        self.assertEqual(len(w.batch), 0)
        self.assertIsNone(w.batch_start_ts)

        # cleanup
        store._fs.delete_dir(os.path.join("/tmp", prefix))

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_get_concurrent_store_worker(self, get_queue):
        get_queue.return_value = (True, "store-worker-http", "https://www.example.com/fomo")
        store = self.build_store(
            name="HTTP", provisioned=True,
            backend_kwargs=HTTPStoreSerializer({
                "endpoint_url": "https://store.example.com",
                "concurrency": 2,
            }).data,
        )
        self.assertEqual(store.concurrency, 2)
        eq = self.get_queues()
        w = eq.get_store_worker(store)
        self.assertIsInstance(w, ConcurrentStoreWorker)
        self.assertEqual(w._threads[0].visibility_timeout, 120)

    @patch("zentral.core.queues.backends.aws_sns_sqs.EventQueues.get_queue")
    def test_get_simple_store_worker(self, get_queue):
        get_queue.return_value = (True, "store-worker-http", "https://www.example.com/fomo")
        store = self.build_store(name="HTTP", provisioned=True)
        self.assertEqual(store.batch_size, 1)
        self.assertEqual(store.concurrency, 1)
        eq = self.get_queues()
        w = eq.get_store_worker(store)
        self.assertIsInstance(w, SimpleStoreWorker)
        self.assertEqual(w._threads[0].visibility_timeout, 120)
