from django.test import TestCase

from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from .utils import force_configuration, force_script_check


class MunkiSerializationTestCase(TestCase, SerializeForEventAssertions):
    def test_serialize_for_event_is_json_native(self):
        for obj in (force_configuration(),
                    force_script_check()):
            with self.subTest(obj._meta.model_name):
                self.assert_serialize_for_event_is_json_native(obj)
