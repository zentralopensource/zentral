import json

from django.test import TestCase
from django.utils.crypto import get_random_string

from tests.mdm.utils import (force_dep_enrollment, force_dep_enrollment_custom_view,
                             force_enrollment_custom_view, force_ota_enrollment, force_realm,
                             force_user_enrollment)
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

    def test_enrollments_share_the_base_payload(self):
        realm = force_realm()
        for enrollment in (force_dep_enrollment(self.mbu),
                           force_ota_enrollment(mbu=self.mbu, realm=realm),
                           force_user_enrollment(self.mbu, realm=realm)):
            with self.subTest(enrollment._meta.model_name):
                d = enrollment.serialize_for_event()
                self.assertEqual(d["pk"], enrollment.pk)
                self.assertEqual(d["name"], enrollment.name)
                self.assertEqual(
                    d["realm"],
                    enrollment.realm.serialize_for_event(keys_only=True) if enrollment.realm else None
                )
                self.assertEqual(d["enrollment_secret"]["pk"], enrollment.enrollment_secret.pk)

    def test_enrollment_serialize_for_event_keys_only(self):
        for enrollment in (force_ota_enrollment(mbu=self.mbu),
                           force_user_enrollment(self.mbu)):
            with self.subTest(enrollment._meta.model_name):
                self.assertEqual(enrollment.serialize_for_event(keys_only=True),
                                 {"pk": enrollment.pk, "name": enrollment.name})
        # the DEP profile uuid is part of the enrollment's identity, so it rides along in both forms
        dep_enrollment = force_dep_enrollment(self.mbu)
        self.assertEqual(dep_enrollment.serialize_for_event(keys_only=True),
                         {"pk": dep_enrollment.pk, "name": dep_enrollment.name,
                          "uuid": str(dep_enrollment.uuid)})
