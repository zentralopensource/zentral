import uuid
from django.test import SimpleTestCase
from zentral.contrib.mdm.events import (DEPEnrollmentRequestEvent,
                                        OTAEnrollmentRequestEvent,
                                        UserEnrollmentRequestEvent)
from zentral.core.events.base import EventMetadata


class TestEnrollmentRequestEvents(SimpleTestCase):
    def test_dep_enrollment_request_linked_objects(self):
        enrollment_uuid = str(uuid.uuid4())
        event = DEPEnrollmentRequestEvent(
            EventMetadata(),
            {"status": "success",
             "enrollment_session": {"pk": 1, "type": "dep", "status": "STARTED"},
             "dep_enrollment": {"pk": 17, "name": "yolo", "uuid": enrollment_uuid}}
        )
        self.assertEqual(event.get_linked_objects_keys(), {"mdm_dep_enrollment": [(17,)]})
        self.assertEqual(event.metadata.serialize()["objects"], {"mdm_dep_enrollment": ["17"]})

    def test_ota_enrollment_request_linked_objects(self):
        event = OTAEnrollmentRequestEvent(
            EventMetadata(),
            {"status": "success",
             "phase": 2,
             "enrollment_session": {"pk": 2, "type": "ota", "status": "PHASE_2"},
             "ota_enrollment": {"pk": 18, "name": "fomo"}}
        )
        self.assertEqual(event.get_linked_objects_keys(), {"mdm_ota_enrollment": [(18,)]})
        self.assertEqual(event.metadata.serialize()["objects"], {"mdm_ota_enrollment": ["18"]})

    def test_user_enrollment_request_linked_objects(self):
        event = UserEnrollmentRequestEvent(
            EventMetadata(),
            {"status": "success",
             "enrollment_session": {"pk": 3, "type": "user", "status": "ACCOUNT_DRIVEN_START"},
             "user_enrollment": {"pk": 19, "name": "godzilla"}}
        )
        self.assertEqual(event.get_linked_objects_keys(), {"mdm_user_enrollment": [(19,)]})
        self.assertEqual(event.metadata.serialize()["objects"], {"mdm_user_enrollment": ["19"]})

    def test_aborted_request_no_linked_objects(self):
        event = DEPEnrollmentRequestEvent(
            EventMetadata(),
            {"status": "failure", "reason": "Device blocked"}
        )
        self.assertEqual(event.get_linked_objects_keys(), {})
        self.assertNotIn("objects", event.metadata.serialize())
