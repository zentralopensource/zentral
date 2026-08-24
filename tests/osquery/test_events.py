from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.osquery.events import (_filter_status_logs, _iter_grouped_status_logs,
                                            OsqueryPackUpdateEvent, OsqueryRequestEvent,
                                            STATUS_LOG_TRUNCATION_FILENAME,
                                            STATUS_LOG_TRUNCATION_SEVERITY)
from zentral.core.events.base import EventMetadata
from zentral.contrib.osquery.models import Configuration, EnrolledMachine, Enrollment


class OsqueryPackUpdateEventTestCase(TestCase):
    def test_report_links_the_pack(self):
        event = OsqueryPackUpdateEvent(EventMetadata(), {"pack": {"pk": 42, "slug": "yolo"}, "result": "created"})
        self.assertEqual(event.get_linked_objects_keys(), {"osquery_pack": [(42,)]})

    def test_report_without_a_pack_links_nothing(self):
        # a stored event from before the pack was added to the report
        event = OsqueryPackUpdateEvent(EventMetadata(), {"result": "created"})
        self.assertEqual(event.get_linked_objects_keys(), {})


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

    # OsqueryStatusEvent

    def test_filter_status_logs(self):
        logs = list(_filter_status_logs([
            {"message": "No severity… Should not happen!"},
            {"severity": 1, "message": "Warning included"},
            {"severity": "0", "message": "Info not included"},
        ], 1))
        self.assertEqual(logs, [
            {"message": "No severity… Should not happen!"},
            {"severity": 1, "message": "Warning included"},
        ])

    # _iter_grouped_status_logs

    @staticmethod
    def build_status_log(message, severity=1, filename="mdfind.mm", line=42, unix_time="1480605737"):
        return {"severity": severity, "filename": filename, "line": line,
                "message": message, "unixTime": unix_time}

    def test_grouped_status_logs_distinct_records_kept(self):
        records = [self.build_status_log("one"), self.build_status_log("two")]
        grouped = list(_iter_grouped_status_logs(records))
        self.assertEqual([r["message"] for r in grouped], ["one", "two"])
        self.assertEqual([r["count"] for r in grouped], [1, 1])

    def test_grouped_status_logs_identical_records_collapsed(self):
        records = [self.build_status_log("same") for _ in range(2000)]
        grouped = list(_iter_grouped_status_logs(records))
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["count"], 2000)
        self.assertEqual(grouped[0]["message"], "same")

    def test_grouped_status_logs_first_occurrence_kept(self):
        records = [self.build_status_log("same", unix_time="1480605737"),
                   self.build_status_log("same", unix_time="1480605999")]
        grouped = list(_iter_grouped_status_logs(records))
        self.assertEqual(grouped[0]["unixTime"], "1480605737")

    def test_grouped_status_logs_differ_on_every_key(self):
        records = [self.build_status_log("m"),
                   self.build_status_log("m", severity=2),
                   self.build_status_log("m", filename="other.cpp"),
                   self.build_status_log("m", line=43)]
        self.assertEqual(len(list(_iter_grouped_status_logs(records))), 4)

    def test_grouped_status_logs_order_preserved(self):
        records = [self.build_status_log("a"), self.build_status_log("b"),
                   self.build_status_log("a"), self.build_status_log("c")]
        grouped = list(_iter_grouped_status_logs(records))
        self.assertEqual([r["message"] for r in grouped], ["a", "b", "c"])
        self.assertEqual([r["count"] for r in grouped], [2, 1, 1])

    def test_grouped_status_logs_capped(self):
        records = [self.build_status_log(f"m{i}") for i in range(5)]
        grouped = list(_iter_grouped_status_logs(records, max_events=3))
        self.assertEqual(len(grouped), 4)
        self.assertEqual([r["message"] for r in grouped[:3]], ["m0", "m1", "m2"])

    def test_grouped_status_logs_truncation_record(self):
        records = [self.build_status_log(f"m{i}") for i in range(4)]
        records.extend(self.build_status_log("m3") for _ in range(9))
        truncation = list(_iter_grouped_status_logs(records, max_events=2))[-1]
        self.assertEqual(truncation["severity"], STATUS_LOG_TRUNCATION_SEVERITY)
        self.assertEqual(truncation["filename"], STATUS_LOG_TRUNCATION_FILENAME)
        self.assertEqual(truncation["count"], 1)
        # m2 once, m3 ten times
        self.assertEqual(truncation["message"], "Status log truncated, 11 record(s) dropped")

    def test_grouped_status_logs_known_group_still_counted_after_cap(self):
        records = [self.build_status_log("kept"), self.build_status_log("dropped")]
        records.extend(self.build_status_log("kept") for _ in range(5))
        grouped = list(_iter_grouped_status_logs(records, max_events=1))
        self.assertEqual(grouped[0]["message"], "kept")
        self.assertEqual(grouped[0]["count"], 6)
        self.assertEqual(grouped[-1]["message"], "Status log truncated, 1 record(s) dropped")

    def test_grouped_status_logs_group_count_bounded(self):
        records = [self.build_status_log(f"m{i}") for i in range(50)]
        grouped = list(_iter_grouped_status_logs(records, max_events=10))
        # 10 groups + the truncation record, whatever the input size
        self.assertEqual(len(grouped), 11)

    def test_grouped_status_logs_no_truncation_record_when_under_cap(self):
        records = [self.build_status_log(f"m{i}") for i in range(3)]
        grouped = list(_iter_grouped_status_logs(records, max_events=3))
        self.assertEqual(len(grouped), 3)
        self.assertNotIn(STATUS_LOG_TRUNCATION_FILENAME, [r["filename"] for r in grouped])

    def test_grouped_status_logs_truncation_record_has_unix_time(self):
        records = [self.build_status_log(f"m{i}", unix_time=str(1480605737 + i)) for i in range(3)]
        truncation = list(_iter_grouped_status_logs(records, max_events=1))[-1]
        self.assertEqual(truncation["unixTime"], "1480605739")

    def test_grouped_status_logs_empty(self):
        self.assertEqual(list(_iter_grouped_status_logs([])), [])
