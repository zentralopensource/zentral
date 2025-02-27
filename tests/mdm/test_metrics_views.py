from datetime import datetime, timedelta
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from prometheus_client.parser import text_string_to_metric_families
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceInformation, InstallProfile
from zentral.contrib.mdm.models import Channel
from .utils import (force_artifact, force_blueprint, force_dep_enrollment_session,
                    force_enrolled_user, force_ota_enrollment_session)


@override_settings(
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage"
)
class MDMMetricsViewsTestCase(TestCase):
    maxDiff = None

    # utility methods

    def _make_authenticated_request(self):
        return self.client.get(
            reverse("mdm_metrics:all"),
            HTTP_AUTHORIZATION=f'Bearer {settings["api"]["metrics_bearer_token"]}',
        )

    def _assertSamples(self, families, samples, only_family=None):
        d = {}
        for family in families:
            if only_family and only_family != family.name:
                continue
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

    def test_enrollment_sessions_metrics(self):
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
            },
            only_family="zentral_mdm_enrollment_sessions",
        )

    def test_commands_metrics(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        session, _, _ = force_dep_enrollment_session(mbu, authenticated=True, completed=True)
        a, (av,) = force_artifact()
        cmd = InstallProfile.create_for_device(session.enrolled_device, av)
        cmd.process_response(
            {"Status": "Acknowledged"}, session, mbu
        )
        ua, (uav, _) = force_artifact(channel=Channel.USER, version_count=2)
        eu = force_enrolled_user(session.enrolled_device)
        cmd = InstallProfile.create_for_target(Target(session.enrolled_device, eu), uav)
        cmd.process_response(
            {"Status": "Error"}, session, mbu
        )
        session3, _, _ = force_dep_enrollment_session(mbu, authenticated=True, completed=True)
        DeviceInformation.create_for_device(session3.enrolled_device)
        response = self._make_authenticated_request()
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
             'zentral_mdm_commands': {
                 ('artifact', a.name,
                  'channel', 'device',
                  'name', 'InstallProfile',
                  'status', 'Acknowledged',
                  'version', '1'): 1.0,
                 ('artifact', ua.name,
                  'channel', 'user',
                  'name', 'InstallProfile',
                  'status', 'Error',
                  'version', '2'): 1.0,
                 ('artifact', '_',
                  'channel', 'device',
                  'name', 'DeviceInformation',
                  'status', '_',
                  'version', '_'): 1.0
             }
            },
            only_family="zentral_mdm_commands"
        )

    def test_enrolled_devices_metrics(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        force_dep_enrollment_session(mbu, authenticated=True, completed=True)
        session, _, _ = force_dep_enrollment_session(mbu, authenticated=True, completed=True)
        enrolled_device = session.enrolled_device
        enrolled_device.blocked_at = datetime.utcnow() - timedelta(days=1)
        enrolled_device.last_seen_at = datetime.utcnow() - timedelta(days=28)
        enrolled_device.supervised = True
        enrolled_device.blueprint = force_blueprint()
        enrolled_device.save()
        bpn = enrolled_device.blueprint.name
        response = self._make_authenticated_request()
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {'zentral_mdm_devices': {
                ('blocked', 'false', 'blueprint', '_', 'le', '1', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '7', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '14', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '30', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '45', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '90', 'platform', 'macOS', 'supervised', '_'): 0.0,
                ('blocked', 'false', 'blueprint', '_', 'le', '+Inf', 'platform', 'macOS', 'supervised', '_'): 1.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '1', 'platform', 'macOS', 'supervised', 'true'): 0.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '7', 'platform', 'macOS', 'supervised', 'true'): 0.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '14', 'platform', 'macOS', 'supervised', 'true'): 0.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '30', 'platform', 'macOS', 'supervised', 'true'): 1.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '45', 'platform', 'macOS', 'supervised', 'true'): 1.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '90', 'platform', 'macOS', 'supervised', 'true'): 1.0,
                ('blocked', 'true', 'blueprint', bpn, 'le', '+Inf', 'platform', 'macOS', 'supervised', 'true'): 1.0,
            }},
            only_family="zentral_mdm_devices",
        )
