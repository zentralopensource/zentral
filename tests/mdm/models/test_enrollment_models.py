import json

from django.test import TestCase
from django.utils.crypto import get_random_string

from tests.mdm.utils import (force_dep_enrollment, force_dep_enrollment_custom_view,
                             force_enrollment_custom_view, force_ota_enrollment, force_user_enrollment)
from zentral.contrib.inventory.models import MetaBusinessUnit


class MDMEnrollmentModelsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

    def test_serialize_for_event_timestamps(self):
        dep_enrollment = force_dep_enrollment(self.mbu)
        for obj in (dep_enrollment,
                    force_ota_enrollment(mbu=self.mbu),
                    force_user_enrollment(self.mbu),
                    force_enrollment_custom_view(),
                    force_dep_enrollment_custom_view(dep_enrollment)):
            with self.subTest(obj._meta.model_name):
                d = obj.serialize_for_event()
                self.assertEqual(d["created_at"], obj.created_at.isoformat())
                self.assertEqual(d["updated_at"], obj.updated_at.isoformat())

    def test_serialize_for_event_is_json_native(self):
        # a datetime left in the payload does not raise in the pipeline — kombu envelopes it — so assert
        # with the stdlib encoder, which does
        dep_enrollment = force_dep_enrollment(self.mbu)
        for obj in (dep_enrollment,
                    force_ota_enrollment(mbu=self.mbu),
                    force_user_enrollment(self.mbu),
                    force_enrollment_custom_view(),
                    force_dep_enrollment_custom_view(dep_enrollment)):
            with self.subTest(obj._meta.model_name):
                json.dumps(obj.serialize_for_event())
