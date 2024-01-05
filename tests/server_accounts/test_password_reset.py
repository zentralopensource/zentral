import json
from unittest.mock import patch, Mock
from django.core import mail
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User
from accounts.password_reset import (get_password_reset_handler,
                                     EmailPasswordResetHandler,
                                     AWSSQSPasswordResetHandler,
                                     GCPPubSubPasswordResetHandler)


class PasswordResetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12),
                                            "{}@zentral.io".format(get_random_string(12)),
                                            get_random_string(12))

    @patch("accounts.password_reset.settings.get")
    def test_get_default_backend_handler(self, settings_get):
        settings_get.return_value = {}
        self.assertIsInstance(get_password_reset_handler(), EmailPasswordResetHandler)

    @patch("accounts.password_reset.settings.get")
    def test_get_email_password_reset_handler(self, settings_get):
        settings_get.return_value = {"backend": "accounts.password_reset.EmailPasswordResetHandler"}
        self.assertIsInstance(get_password_reset_handler(), EmailPasswordResetHandler)

    def test_email_send_password_reset(self):
        handler = EmailPasswordResetHandler({})
        handler.send_password_reset(self.user)
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Password reset on Zentral")
        self.assertIn(f"Your username, in case you've forgotten: {self.user.username}", email.body)

    def test_email_send_invitation(self):
        handler = EmailPasswordResetHandler({})
        handler.send_password_reset(self.user, invitation=True)
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Invitation to Zentral")
        self.assertIn(f"Your username: {self.user.username}", email.body)

    @patch("accounts.password_reset.settings.get")
    def test_get_aws_sqs_password_reset_handler(self, settings_get):
        settings_get.return_value = {
            "backend": "accounts.password_reset.AWSSQSPasswordResetHandler",
            "queue_url": "https://sqs.eu-central-1.amazonaws.com/000000000000/PasswordReset"
        }
        handler = get_password_reset_handler()
        self.assertIsInstance(handler, AWSSQSPasswordResetHandler)
        self.assertEqual(handler.queue_url, "https://sqs.eu-central-1.amazonaws.com/000000000000/PasswordReset")
        self.assertEqual(handler.region_name, "eu-central-1")

    @patch("boto3.client")
    def test_aws_sqs_send_password_reset(self, bc):
        client = Mock()
        bc.return_value = client
        handler = AWSSQSPasswordResetHandler(
            {"queue_url": "https://sqs.eu-central-1.amazonaws.com/000000000000/PasswordReset"}
        )
        handler.send_password_reset(self.user)
        self.assertEqual(len(client.send_message.call_args_list), 1)
        kwargs = client.send_message.call_args_list[0][1]
        self.assertEqual(kwargs["QueueUrl"], "https://sqs.eu-central-1.amazonaws.com/000000000000/PasswordReset")
        json_payload = kwargs["MessageBody"]
        payload = json.loads(json_payload)
        reset_url = payload.pop("reset_url")
        self.assertEqual(
            payload,
            {"email": self.user.email,
             "username": self.user.username,
             "fqdn": "zentral",
             "invitation": False}
        )
        self.assertTrue(reset_url.startswith("https://"))

    @patch("accounts.password_reset.settings.get")
    def test_get_gcp_pub_sub_password_reset_handler(self, settings_get):
        settings_get.return_value = {
            "backend": "accounts.password_reset.GCPPubSubPasswordResetHandler",
            "topic": "projects/the-project/topics/password-reset",
        }
        handler = get_password_reset_handler()
        self.assertIsInstance(handler, GCPPubSubPasswordResetHandler)
        self.assertEqual(handler.topic, "projects/the-project/topics/password-reset")

    @patch("google.cloud.pubsub_v1.PublisherClient")
    def test_gcp_pub_sub_send_password_reset(self, pc):
        client = Mock()
        pc.return_value = client
        handler = GCPPubSubPasswordResetHandler({"topic": "yolo"})
        handler.send_password_reset(self.user)
        self.assertEqual(len(client.publish.call_args_list), 1)
        topic, json_payload = client.publish.call_args_list[0][0]
        self.assertEqual(topic, "yolo")
        payload = json.loads(json_payload)
        reset_url = payload.pop("reset_url")
        self.assertEqual(
            payload,
            {"email": self.user.email,
             "username": self.user.username,
             "fqdn": "zentral",
             "invitation": False}
        )
        self.assertTrue(reset_url.startswith("https://"))
