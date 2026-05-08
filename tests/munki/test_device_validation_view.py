import json
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from .utils import force_configuration, force_enrollment


class EnrollmentViewDeviceCheckTestCase(TestCase):
    """Device-validation branch of EnrollmentView (serial_number + device_token in POST body)."""

    @classmethod
    def setUpTestData(cls):
        cls.enrollment = force_enrollment()
        cls.url = reverse("munki_public:enrollment")

    def _post(self, data, secret=None):
        headers = {}
        if secret is not None:
            headers["HTTP_AUTHORIZATION"] = f"ZtlEnrollmentSecret {secret}"
        return self.client.post(
            self.url,
            json.dumps(data),
            content_type="application/json",
            **headers,
        )

    def _make_devicecheck_enrollment(self):
        """Return an Enrollment whose Configuration has DeviceCheck fields set."""
        configuration = force_configuration(
            # Not a real encrypted blob — tests mock validate_device_token_with_apple.
            devicecheck_private_key="fakesecretengine$fakeencryptedvalue",
            devicecheck_private_key_id=get_random_string(10),
            devicecheck_team_id=get_random_string(10),
        )
        return force_enrollment(configuration=configuration)

    # --- no serial_number → DeviceCheck skipped, enrollment info returned ---

    def test_no_serial_number_skips_devicecheck(self):
        response = self._post(
            {"device_token": "abc"},
            secret=self.enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("pk", response.json())

    # --- serial_number present, DeviceCheck not configured → skipped ---

    def test_serial_number_without_devicecheck_configured_skips_validation(self):
        response = self._post(
            {"serial_number": get_random_string(12)},
            secret=self.enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("pk", response.json())

    # --- serial_number present, DeviceCheck configured, device_token missing ---

    def test_serial_number_without_device_token_returns_400(self):
        enrollment = self._make_devicecheck_enrollment()
        response = self._post(
            {"serial_number": get_random_string(12)},
            secret=enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "device_token required.")

    # --- valid device token ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_valid_device_token(self, mock_validate, mock_post_event):
        mock_validate.return_value = True
        enrollment = self._make_devicecheck_enrollment()
        serial_number = get_random_string(12)
        response = self._post(
            {"serial_number": serial_number, "device_token": "YWJj"},
            secret=enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("pk", response.json())
        mock_validate.assert_called_once_with(enrollment.configuration, "YWJj")
        mock_post_event.assert_called_once()
        msn, _, _ = mock_post_event.call_args.args
        self.assertEqual(msn, serial_number)
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": enrollment.pk},
            "result": "valid",
        })

    # --- invalid device token (Apple rejected) ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_invalid_device_token(self, mock_validate, mock_post_event):
        mock_validate.return_value = False
        enrollment = self._make_devicecheck_enrollment()
        serial_number = get_random_string(12)
        response = self._post(
            {"serial_number": serial_number, "device_token": "YWJj"},
            secret=enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Device validation failed.")
        mock_post_event.assert_called_once()
        msn, _, _ = mock_post_event.call_args.args
        self.assertEqual(msn, serial_number)
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": enrollment.pk},
            "result": "invalid",
        })

    # --- upstream / network error ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_upstream_error(self, mock_validate, mock_post_event):
        mock_validate.return_value = None
        enrollment = self._make_devicecheck_enrollment()
        serial_number = get_random_string(12)
        response = self._post(
            {"serial_number": serial_number, "device_token": "YWJj"},
            secret=enrollment.secret.secret,
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "DeviceCheck upstream error.")
        mock_post_event.assert_called_once()
        msn, _, _ = mock_post_event.call_args.args
        self.assertEqual(msn, serial_number)
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": enrollment.pk},
            "result": "error",
        })
