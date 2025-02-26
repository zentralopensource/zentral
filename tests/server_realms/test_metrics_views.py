from django.urls import reverse
from django.test import TestCase, override_settings
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import settings
from .utils import force_realm, force_realm_group, force_realm_user


@override_settings(
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage"
)
class RealmsMetricsViewsTestCase(TestCase):
    # utility methods

    def _make_authenticated_request(self):
        return self.client.get(
            reverse("realms_metrics:all"),
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
        response = self.client.get(reverse("realms_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_metrics_permission_ok(self):
        response = self._make_authenticated_request()
        self.assertEqual(response.status_code, 200)

    def test_metrics(self):
        realm = force_realm()  # one realm without SCIM
        realm_group = force_realm_group(realm=realm)  # one realm group without SCIM
        force_realm_user(realm)  # one non-SCIM user
        scim_realm = force_realm()  # one realm with SCIM
        scim_realm.scim_enabled = True
        scim_realm.enabled_for_login = True
        scim_realm.save()
        _, scim_realm_user = force_realm_user(realm=scim_realm)  # one SCIM user
        scim_realm_group = force_realm_group(realm=scim_realm)  # one SCIM realm group
        scim_realm_user.groups.add(scim_realm_group)  # one SCIM realm group member
        response = self._make_authenticated_request()
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                "zentral_realm_group_members": {
                    ("realm", realm.name,
                     "realm_group", realm_group.display_name,
                     "scim_managed", "false"): 0.0,
                    ("realm", scim_realm.name,
                     "realm_group", scim_realm_group.display_name,
                     "scim_managed", "true"): 1.0},
                "zentral_realm_groups": {
                    ("realm", scim_realm.name,
                     "scim_managed", "true"): 1.0,
                    ("realm", realm.name,
                     "scim_managed", "false"): 1.0,
                },
                "zentral_realm_users": {
                    ("realm", scim_realm.name,
                     "scim_active", "true",
                     "scim_managed", "true"): 1.0,
                    ("realm", realm.name,
                     "scim_active", "false",
                     "scim_managed", "false"): 1.0
                },
                "zentral_realms": {
                    ("backend", "ldap",
                     "enabled_for_login", "false",
                     "scim_enabled", "false",
                     "user_portal", "false"): 1.0,
                    ("backend", "ldap",
                     "enabled_for_login", "true",
                     "scim_enabled", "true",
                     "user_portal", "false"): 1.0
                },
            },
        )
