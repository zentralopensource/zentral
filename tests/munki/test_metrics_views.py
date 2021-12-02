from datetime import datetime
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.contrib.munki.models import ManagedInstall
from zentral.conf import settings


class MunkiMetricsViewsTestCase(TestCase):
    # utility methods

    def _force_managed_install(self, failed=False, count=1, reinstall=False):
        return ManagedInstall.objects.create(
            machine_serial_number=get_random_string(),
            name=get_random_string(),
            installed_version=get_random_string(),
            installed_at=datetime.now(),
            failed_version=get_random_string() if failed else None,
            failed_at=datetime.now() if failed else None,
            reinstall=reinstall,
        )

    def _make_authenticated_request(self):
        return self.client.get(reverse("munki_metrics:all"),
                               HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}')

    # metrics

    def test_metrics_permission_denied(self):
        response = self.client.get(reverse("munki_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_installed_pkginfos(self):
        mi = self._force_managed_install()
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_munki_installed_pkginfos":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["name"], mi.name)
                self.assertEqual(sample.labels["version"], mi.installed_version)
                self.assertEqual(sample.labels["reinstall"], "no" if not mi.reinstall else "yes")
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)

    def test_failed_pkginfos(self):
        mi = self._force_managed_install(failed=True)
        response = self._make_authenticated_request()
        for family in text_string_to_metric_families(response.content.decode("utf-8")):
            if family.name != "zentral_munki_failed_pkginfos":
                continue
            else:
                self.assertEqual(len(family.samples), 1)
                sample = family.samples[0]
                self.assertEqual(sample.value, 1)
                self.assertEqual(sample.labels["name"], mi.name)
                self.assertEqual(sample.labels["version"], mi.failed_version)
                break
        else:
            raise AssertionError("could not find expected metric family")
        self.assertEqual(response.status_code, 200)
