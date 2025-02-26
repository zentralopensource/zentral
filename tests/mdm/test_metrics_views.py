from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_dep_enrollment_session, force_ota_enrollment_session


@override_settings(
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage"
)
class MDMMetricsViewsTestCase(TestCase):
    # utility methods

    def _make_authenticated_request(self):
        return self.client.get(
            reverse("mdm_metrics:all"),
            HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}',
        )

    def _assertSamples(self, families, samples):
        d = {}
        for family in families:
            sample_dict = d.setdefault(family.name, {})
            for sample in family.samples:
                serialized_sample_items = []
                for label in sorted(sample.labels.keys()):
                    serialized_sample_items.append(label)
                    serialized_sample_items.append(sample.labels[label])
                sample_dict[tuple(serialized_sample_items)] = sample.value
        self.assertEqual(d, samples)

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("mdm_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_metrics(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        force_dep_enrollment_session(mbu)
        dep_session, _, _ = force_dep_enrollment_session(mbu, authenticated=True, completed=True, realm_user=True)
        dep_realm = dep_session.realm_user.realm
        ota_session, _, _ = force_ota_enrollment_session(mbu, authenticated=True, realm_user=True)
        ota_realm = ota_session.realm_user.realm
        response = self._make_authenticated_request()
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_mdm_enrollment_sessions': {
                    ('realm', '_', 'status', 'STARTED', 'type', 'DEP'): 1.0,
                    ('realm', dep_realm.name, 'status', 'COMPLETED', 'type', 'DEP'): 1.0,
                    ('realm', ota_realm.name, 'status', 'AUTHENTICATED', 'type', 'OTA'): 1.0,
                },
            }
        )
