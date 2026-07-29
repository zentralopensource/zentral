import datetime

from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import DeviceInformation
from tests.mdm.utils import (force_artifact, force_blueprint, force_blueprint_artifact,
                             force_dep_enrollment_session, force_filevault_config, force_location,
                             force_package, force_recovery_password_config,
                             force_software_update, force_software_update_enforcement)
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions


class MDMConfigAndArtifactModelsTestCase(TestCase, SerializeForEventAssertions):

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    def test_serialize_for_event_is_json_native(self):
        artifact, (artifact_version,) = force_artifact()
        blueprint_artifact, _, _ = force_blueprint_artifact()
        session, _, _ = force_dep_enrollment_session(self.mbu, authenticated=True, completed=True)
        device_command = DeviceInformation.create_for_device(session.enrolled_device).db_command
        # a bounded availability exercises both DateRangeField edges
        software_update = force_software_update(
            device_id=get_random_string(12),
            version="17.1.2",
            posting_date=datetime.date(2024, 1, 1),
            expiration_date=datetime.date(2024, 2, 1),
        )
        for obj in (force_filevault_config(),
                    force_recovery_password_config(),
                    force_software_update_enforcement(),
                    force_blueprint(),
                    force_location(),
                    artifact,
                    artifact_version,
                    blueprint_artifact,
                    force_package(),
                    device_command,
                    software_update):
            with self.subTest(obj._meta.model_name):
                self.assert_serialize_for_event_is_json_native(obj)
