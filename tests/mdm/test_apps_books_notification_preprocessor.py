import datetime
from unittest.mock import call, patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.events import AssetCountNotificationEvent
from zentral.contrib.mdm.models import ServerToken
from zentral.contrib.mdm.preprocessors import get_preprocessors


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
