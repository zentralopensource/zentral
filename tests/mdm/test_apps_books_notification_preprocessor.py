import datetime
from unittest.mock import call, patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.events import (AssetAssociationEvent, AssetAssociationErrorEvent,
                                        AssetCountNotificationEvent,
                                        AssetDisassociationEvent, AssetDisassociationErrorEvent,
                                        AssetRevocationEvent, AssetRevocationErrorEvent)
from zentral.contrib.mdm.models import ServerToken
from zentral.contrib.mdm.preprocessors import get_preprocessors
from zentral.core.incidents.models import Severity


class MDMAppsBooksNotificationPreprocessorTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.server_token = ServerToken(
            token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
            token=get_random_string(12),
            token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            location_name=get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        cls.server_token.set_notification_auth_token()
        cls.server_token.save()
        cls.preprocessor = list(get_preprocessors())[0]

    @patch("zentral.contrib.mdm.preprocessors.logger.error")
    def test_bad_raw_event(self, logger_error):
        events = list(self.preprocessor.process_raw_event({}))
        self.assertEqual(len(events), 0)
        logger_error.assert_called_once_with("Bad raw event")

    @patch("zentral.contrib.mdm.preprocessors.logger.error")
    def test_missing_or_bad_notification_type(self, logger_error):
        events = list(self.preprocessor.process_raw_event({"data": {}}))
        self.assertEqual(len(events), 0)
        logger_error.assert_called_once_with("Missing or bad notification type")

    @patch("zentral.contrib.mdm.preprocessors.logger.warning")
    def test_unknown_notification_type(self, logger_warning):
        events = list(self.preprocessor.process_raw_event({"data": {"notificationType": "YOLO"}}))
        self.assertEqual(len(events), 0)
        logger_warning.assert_called_once_with("Unknown notification type: %s", "YOLO")

    @patch("zentral.contrib.mdm.preprocessors.logger.error")
    def test_missing_or_bad_mdm_info_id(self, logger_error):
        events = list(self.preprocessor.process_raw_event({"data": {"notificationType": "ASSET_COUNT",
                                                                    "notificationId": str(uuid.uuid4())}}))
        self.assertEqual(len(events), 0)
        logger_error.assert_has_calls([
            call("Missing or bad MDM Info ID"),
            call("Unknown server token"),
        ])

    @patch("zentral.contrib.mdm.preprocessors.logger.error")
    def test_unknown_mdm_info_id(self, logger_error):
        events = list(self.preprocessor.process_raw_event({"data": {"notificationType": "ASSET_COUNT",
                                                                    "notificationId": str(uuid.uuid4())},
                                                           "server_token": {"mdm_info_id": str(uuid.uuid4())}}))
        self.assertEqual(len(events), 0)
        logger_error.assert_has_calls([
            call("Unknown MDM Info ID"),
            call("Unknown server token"),
        ])

    @patch("zentral.contrib.mdm.preprocessors.logger.warning")
    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.update_server_token_asset_counts")
    def test_asset_count_notification(self, update_server_token_asset_counts, server_token_cache_get, logger_warning):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        update_server_token_asset_counts.return_value = []
        notification_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_COUNT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                       "adamId": "361304891",
                       "countDelta": 1,
                       "pricingParam": "STDQ"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetCountNotificationEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(event.payload["asset"]["adam_id"], "361304891")
        self.assertEqual(event.metadata.created_at, now)
        update_server_token_asset_counts.assert_called_once_with(
            self.server_token, client, "361304891", "STDQ",
            {"available_count": 1, "total_count": 1},
            notification_id
        )
        # cached
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_COUNT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                       "adamId": "361304891",
                       "countDelta": 1,
                       "pricingParam": "STDQ"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 0)
        logger_warning.assert_called_once_with("Notification %s already received", notification_id)

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.associate_server_token_asset")
    def test_asset_management_associate_success(self, associate_server_token_asset, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        associate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "eventId": event_id,
                         "result": "SUCCESS",
                         "type": "ASSOCIATE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetAssociationEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_association")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.NONE)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.metadata.created_at, now)
        associate_server_token_asset.assert_called_once_with(
            self.server_token, client, "409203825", "STDQ",
            set(["C02000000000"]), event_id, notification_id
        )

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.clear_on_the_fly_assignment")
    @patch("zentral.contrib.mdm.preprocessors.associate_server_token_asset")
    def test_asset_management_associate_failure(
        self,
        associate_server_token_asset,
        clear_on_the_fly_assignment,
        server_token_cache_get
    ):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        associate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "error": {
                             "errorMessage": "There aren't enough assets available to complete this association.",
                             "errorNumber": 9709
                         },
                         "eventId": event_id,
                         "result": "FAILURE",
                         "type": "ASSOCIATE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetAssociationErrorEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_association")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.MAJOR)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.payload["error"]["message"],
                         "There aren't enough assets available to complete this association.")
        self.assertEqual(event.payload["error"]["number"], 9709)
        self.assertEqual(event.metadata.created_at, now)
        associate_server_token_asset.assert_not_called()
        clear_on_the_fly_assignment.assert_called_once_with(
            self.server_token, "C02000000000", "409203825", "STDQ", "associate error"
        )

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.disassociate_server_token_asset")
    def test_asset_management_disassociate_success(self, disassociate_server_token_asset, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        disassociate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "eventId": event_id,
                         "result": "SUCCESS",
                         "type": "DISASSOCIATE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetDisassociationEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_disassociation")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.NONE)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.metadata.created_at, now)
        disassociate_server_token_asset.assert_called_once_with(
            self.server_token, client, "409203825", "STDQ",
            set(["C02000000000"]), event_id, notification_id
        )

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.disassociate_server_token_asset")
    def test_asset_management_disassociate_failure(self, disassociate_server_token_asset, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        disassociate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "error": {
                             "errorMessage": "Oups",
                             "errorNumber": 1100
                         },
                         "eventId": event_id,
                         "result": "FAILURE",
                         "type": "DISASSOCIATE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetDisassociationErrorEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_disassociation")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.MAJOR)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.payload["error"]["message"], "Oups")
        self.assertEqual(event.payload["error"]["number"], 1100)
        self.assertEqual(event.metadata.created_at, now)
        disassociate_server_token_asset.assert_not_called()

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.disassociate_server_token_asset")
    def test_asset_management_revoke_success(self, disassociate_server_token_asset, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        disassociate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "eventId": event_id,
                         "result": "SUCCESS",
                         "type": "REVOKE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetRevocationEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_revocation")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.NONE)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.metadata.created_at, now)
        disassociate_server_token_asset.assert_called_once_with(
            self.server_token, client, "409203825", "STDQ",
            set(["C02000000000"]), event_id, notification_id
        )

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    @patch("zentral.contrib.mdm.preprocessors.disassociate_server_token_asset")
    def test_asset_management_revoke_failure(self, disassociate_server_token_asset, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        disassociate_server_token_asset.return_value = []
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "error": {
                             "errorMessage": "Oups",
                             "errorNumber": 1100
                         },
                         "eventId": event_id,
                         "result": "FAILURE",
                         "type": "REVOKE"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, AssetRevocationErrorEvent)
        self.assertEqual(event.metadata.request.user_agent, "yolo")
        self.assertEqual(event.metadata.request.ip, "127.0.0.1")
        self.assertEqual(len(event.metadata.incident_updates), 1)
        iu = event.metadata.incident_updates[0]
        self.assertEqual(iu.incident_type, "mdm_asset_revocation")
        self.assertEqual(iu.key, {"mdm_st_pk": self.server_token.pk,
                                  "mdm_adam_id": "409203825",
                                  "mdm_pricing_param": "STDQ"})
        self.assertEqual(iu.severity, Severity.MAJOR)
        self.assertEqual(event.payload["asset"]["adam_id"], "409203825")
        self.assertEqual(event.payload["asset"]["pricing_param"], "STDQ")
        self.assertEqual(event.payload["error"]["message"], "Oups")
        self.assertEqual(event.payload["error"]["number"], 1100)
        self.assertEqual(event.metadata.created_at, now)
        disassociate_server_token_asset.assert_not_called()

    @patch("zentral.contrib.mdm.preprocessors.server_token_cache.get")
    def test_unknown_asset_management_notification(self, server_token_cache_get):
        client = Mock()
        server_token_cache_get.return_value = self.server_token, client
        notification_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        events = list(self.preprocessor.process_raw_event({
            "data": {"notificationType": "ASSET_MANAGEMENT",
                     "notificationId": notification_id,
                     "uId": "2049025000431439",
                     "notification": {
                         "assignments": [
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "serialNumber": "C02000000000"},
                             {"adamId": "409203825",
                              "pricingParam": "STDQ",
                              "clientUserId": "111"},  # Ignored
                         ],
                         "eventId": event_id,
                         "result": "SUCCESS",
                         "type": "YOLOFOMO"
                     }},
            "metadata": {"request": {"user_agent": "yolo", "ip": "127.0.0.1"},
                         "created_at": now.isoformat()},
            "server_token": {"mdm_info_id": str(self.server_token.mdm_info_id)}
        }))
        self.assertEqual(len(events), 0)
