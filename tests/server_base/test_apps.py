from django.test import SimpleTestCase
from django.apps import apps
from zentral.utils.apps import ZentralAppConfig


class TestZentralApps(SimpleTestCase):
    maxDiff = None
    expected_apps = [
        "accounts",
        "compliance_checks",
        "incidents",
        "inventory",
        "jamf",
        "mdm",
        "monolith",
        "munki",
        "probes",
        "puppet",
        "osquery",
        "realms",
        "santa",
        "wsone",
    ]

    def test_zentral_apps(self):
        found_apps = []
        ok_apps = []
        for name, app_config in apps.app_configs.items():
            if name in self.expected_apps:
                found_apps.append(name)
                if isinstance(app_config, ZentralAppConfig):
                    ok_apps.append(name)
        self.assertEqual(found_apps, ok_apps)
        self.assertEqual(sorted(found_apps), sorted(self.expected_apps))
