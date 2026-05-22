from unittest.mock import patch

from django.test import RequestFactory, TestCase

from zentral.contrib.munki.public_views import MunkiEnrollmentSecretAuthentication


class MunkiEnrollmentSecretAuthenticationTestCase(TestCase):
    def test_enrollment_event_type_derived_from_enrollment_model(self):
        self.assertEqual(MunkiEnrollmentSecretAuthentication.enrollment_event_type, "munki_enrollment")

    def test_authenticate_missing_enrollment_model_raises_not_implemented(self):
        auth = MunkiEnrollmentSecretAuthentication()
        request = RequestFactory().get("/")
        with patch.object(MunkiEnrollmentSecretAuthentication, "enrollment_model", None):
            with self.assertRaises(NotImplementedError):
                auth.authenticate(request)
