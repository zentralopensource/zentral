from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.osquery.events import OsqueryRequestEvent
from zentral.contrib.osquery.models import Configuration, EnrolledMachine, Enrollment


class OsqueryEventsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))

    def force_configuration(self, options=None):
        kwargs = {"name": get_random_string(256)}
        if options:
            kwargs["options"] = options
        return Configuration.objects.create(**kwargs)

    def force_enrolled_machine(self, osquery_version="1.2.3", platform_mask=21, configuration=None):
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        if not configuration:
            configuration = self.force_configuration()
        enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        return EnrolledMachine.objects.create(
            enrollment=enrollment,
            serial_number=get_random_string(12),
            node_key=get_random_string(12),
            osquery_version=osquery_version,
            platform_mask=platform_mask
        )

    # OsqueryRequestEvent

    def test_osquery_request_heartbeat_timeout_no_enrolled_machine(self):
        self.assertIsNone(OsqueryRequestEvent.get_machine_heartbeat_timeout(get_random_string(12)))

    def test_osquery_request_default_heartbeat_timeout(self):
        enrolled_machine = self.force_enrolled_machine()
        self.assertEqual(OsqueryRequestEvent.get_machine_heartbeat_timeout(enrolled_machine.serial_number), 2400)

    def test_osquery_request_custom_heartbeat_timeout_int(self):
        configuration = self.force_configuration(options={"config_refresh": 60, "distributed_interval": 12345})
        enrolled_machine = self.force_enrolled_machine(configuration=configuration)
        self.assertEqual(OsqueryRequestEvent.get_machine_heartbeat_timeout(enrolled_machine.serial_number), 24690)

    def test_osquery_request_custom_heartbeat_timeout_str(self):
        configuration = self.force_configuration(options={"config_refresh": "7200", "distributed_interval": "1234"})
        enrolled_machine = self.force_enrolled_machine(configuration=configuration)
        self.assertEqual(OsqueryRequestEvent.get_machine_heartbeat_timeout(enrolled_machine.serial_number), 14400)
