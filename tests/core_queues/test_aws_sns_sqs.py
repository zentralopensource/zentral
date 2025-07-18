from datetime import datetime
import json
from unittest.mock import patch
import boto3
from botocore.stub import Stubber
from django.test import TestCase
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from zentral.core.queues.backends.aws_sns_sqs import EventQueues
from zentral.core.stores.models import Store


class AWSSNSSQSQueuesTestCase(TestCase):
    maxDiff = None

    @staticmethod
    def build_store(name=None, event_filters=None, provisioned=False):
        if event_filters is None:
            event_filters = {}
        name = name or get_random_string(12)
        store = Store.objects.create(
            name=name,
            slug=slugify(name),
            event_filters=event_filters,
            backend="HTTP",
            backend_kwargs={}
        )
        store.set_backend_kwargs({"endpoint_url": "https://www.example.com"})
        if provisioned:
            store.provisioning_uid = get_random_string(12)
        store.save()
        return store.get_backend(load=True)

    @staticmethod
    def get_queues(config=None):
        if config is None:
            config = {
                "prefix": "prefix-",
                "tags": {"un": "1"},
                "region_name": "eu-central-1",
                "predefined_queues": {
                    "store-enriched-events-opensearch": "https://www.example.com/yolo"
                },
                "predefined_topics": {
                    "enriched-events": "arn:yolo"
                }
            }
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
        self.assertEqual(list(eq.client_kwargs.keys()), ["config", "region_name"])
        self.assertEqual(eq.client_kwargs["region_name"], "eu-central-1")
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
