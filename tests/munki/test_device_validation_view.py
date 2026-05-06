import json
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from .utils import force_configuration, force_enrollment, make_enrolled_machine


class DeviceValidationViewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Base enrollment without DeviceCheck — used for auth and not-configured tests.
        cls.enrollment = force_enrollment()
        cls.enrolled_machine = make_enrolled_machine(enrollment=cls.enrollment)
        cls.url = reverse("munki_public:validate_device")

    def _post(self, data, token=None):
        headers = {}
        if token is not None:
            headers["HTTP_AUTHORIZATION"] = f"MunkiEnrolledMachine {token}"
        return self.client.post(
            self.url,
            json.dumps(data),
            content_type="application/json",
            **headers,
        )

    def _make_devicecheck_em(self):
        """Return an EnrolledMachine whose Configuration has DeviceCheck fields set."""
        configuration = force_configuration(
            # The value is intentionally not a real encrypted blob — the view tests
            # mock validate_device_token_with_apple so decryption never runs.
            devicecheck_private_key="fakesecretengine$fakeencryptedvalue",
            devicecheck_private_key_id=get_random_string(10),
            devicecheck_team_id=get_random_string(10),
        )
        return make_enrolled_machine(enrollment=force_enrollment(configuration=configuration))

    # --- authentication ---

    def test_missing_auth_header(self):
        response = self._post({"device_token": "abc"})
        self.assertEqual(response.status_code, 403)

    def test_unknown_token(self):
        response = self._post({"device_token": "abc"}, token=get_random_string(34))
        self.assertEqual(response.status_code, 403)

    # --- DeviceCheck not configured ---

    def test_devicecheck_not_configured(self):
        response = self._post({"device_token": "abc"}, token=self.enrolled_machine.token)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "DeviceCheck not configured.")

    # --- invalid request body ---

    def test_missing_device_token_field(self):
        em = self._make_devicecheck_em()
        response = self._post({}, token=em.token)
        self.assertEqual(response.status_code, 400)

    def test_get_method_not_allowed(self):
        em = self._make_devicecheck_em()
        response = self.client.get(
            self.url,
            HTTP_AUTHORIZATION=f"MunkiEnrolledMachine {em.token}",
        )
        self.assertEqual(response.status_code, 405)

    # --- valid device token ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_valid_device_token(self, mock_validate, mock_post_event):
        mock_validate.return_value = True
        em = self._make_devicecheck_em()
        response = self._post({"device_token": "YWJj"}, token=em.token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})
        mock_validate.assert_called_once_with(em.enrollment.configuration, "YWJj")
        mock_post_event.assert_called_once()
        msn, _, _ = mock_post_event.call_args.args
        self.assertEqual(msn, em.serial_number)
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": em.enrollment.pk},
            "result": "valid",
        })

    # --- invalid device token (Apple rejected it) ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_invalid_device_token(self, mock_validate, mock_post_event):
        mock_validate.return_value = False
        em = self._make_devicecheck_em()
        response = self._post({"device_token": "YWJj"}, token=em.token)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Device validation failed.")
        mock_post_event.assert_called_once()
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": em.enrollment.pk},
            "result": "invalid",
        })

    # --- upstream / network error ---

    @patch("zentral.contrib.munki.public_views.post_munki_request_event")
    @patch("zentral.contrib.munki.public_views.validate_device_token_with_apple")
    def test_upstream_error(self, mock_validate, mock_post_event):
        mock_validate.return_value = None
        em = self._make_devicecheck_em()
        response = self._post({"device_token": "YWJj"}, token=em.token)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["detail"], "DeviceCheck upstream error.")
        mock_post_event.assert_called_once()
        self.assertEqual(mock_post_event.call_args.kwargs, {
            "request_type": "device_validation",
            "enrollment": {"pk": em.enrollment.pk},
            "result": "error",
        })
