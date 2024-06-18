from datetime import datetime
from dateutil import parser
from django.test import SimpleTestCase
from zentral.core.stores.backends.azure_log_analytics import datetime_to_iso8601z_truncated_to_milliseconds


class TestDateTimeConverstion(SimpleTestCase):
    def _assert_ts_equals(self, ts_list):
        for in_ts, out_ts in ts_list:
            self.assertEqual(
                datetime_to_iso8601z_truncated_to_milliseconds(parser.parse(in_ts)),
                out_ts
            )

    def test_timezone_conversion(self):
        self._assert_ts_equals((
            ("2019-01-12T11:11:11.319+02:00", "2019-01-12T09:11:11.319Z"),
            ("2019-01-12T11:11:11.319+00:00", "2019-01-12T11:11:11.319Z"),
            ("2019-01-12T11:11:11Z", "2019-01-12T11:11:11Z"),
        ))

    def test_microseconds_to_milliseconds(self):
        self._assert_ts_equals((
            ("2019-01-12T11:11:11.999999", "2019-01-12T11:11:12Z"),
            ("2019-01-12T11:11:11.123111", "2019-01-12T11:11:11.123Z"),
            ("2019-01-12T11:11:11.000999+00:00", "2019-01-12T11:11:11.001Z"),
            ("2019-01-12T11:11:11.000234+00:00", "2019-01-12T11:11:11Z"),
        ))

    def test_naive_datetime(self):
        self.assertEqual(
            datetime_to_iso8601z_truncated_to_milliseconds(datetime(2019, 1, 1, 0, 0, 0).replace(tzinfo=None)),
            "2019-01-01T00:00:00Z"
        )
