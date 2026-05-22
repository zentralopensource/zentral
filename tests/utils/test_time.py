from datetime import datetime, timezone

from django.test import SimpleTestCase, override_settings

from zentral.utils.time import (
    duration_repr,
    naive_utc_fromisoformat,
    naive_utcfromtimestamp,
    naive_utcnow,
)


class TimeTestCase(SimpleTestCase):
    def test_empty(self):
        self.assertEqual("", duration_repr(0))

    def test_full(self):
        self.assertEqual("14d 23h 24m 31s", duration_repr(1293871))

    # naive_utcnow

    def test_naive_utcnow_is_naive(self):
        self.assertIsNone(naive_utcnow().tzinfo)

    def test_naive_utcnow_matches_utc(self):
        before = datetime.now(timezone.utc).replace(tzinfo=None)
        value = naive_utcnow()
        after = datetime.now(timezone.utc).replace(tzinfo=None)
        self.assertLessEqual(before, value)
        self.assertLessEqual(value, after)

    # naive_utcfromtimestamp

    def test_naive_utcfromtimestamp_epoch(self):
        self.assertEqual(naive_utcfromtimestamp(0), datetime(1970, 1, 1))

    def test_naive_utcfromtimestamp_is_naive(self):
        self.assertIsNone(naive_utcfromtimestamp(0).tzinfo)

    def test_naive_utcfromtimestamp_known_value(self):
        # 2009-02-13T23:31:30Z (1234567890 epoch milestone)
        self.assertEqual(
            naive_utcfromtimestamp(1234567890),
            datetime(2009, 2, 13, 23, 31, 30),
        )

    def test_naive_utcfromtimestamp_float(self):
        self.assertEqual(
            naive_utcfromtimestamp(0.5),
            datetime(1970, 1, 1, 0, 0, 0, 500000),
        )

    # naive_utc_fromisoformat
    #
    # Pinning TIME_ZONE='UTC' makes the make_naive() fallback deterministic.
    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_bare(self):
        # No tz suffix → fromisoformat returns naive → returned as-is.
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02T03:04:05"),
            datetime(2026, 1, 2, 3, 4, 5),
        )

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_result_is_naive(self):
        self.assertIsNone(naive_utc_fromisoformat("2026-01-02T03:04:05Z").tzinfo)

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_z_suffix(self):
        # Z-suffix → aware UTC → stripped to naive UTC components.
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02T03:04:05Z"),
            datetime(2026, 1, 2, 3, 4, 5),
        )

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_positive_offset(self):
        # 03:04:05+02:00 is 01:04:05 UTC; make_naive converts to TIME_ZONE=UTC.
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02T03:04:05+02:00"),
            datetime(2026, 1, 2, 1, 4, 5),
        )

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_negative_offset(self):
        # 03:04:05-05:00 is 08:04:05 UTC.
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02T03:04:05-05:00"),
            datetime(2026, 1, 2, 8, 4, 5),
        )

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_microseconds_preserved(self):
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02T03:04:05.123456Z"),
            datetime(2026, 1, 2, 3, 4, 5, 123456),
        )

    @override_settings(TIME_ZONE="UTC")
    def test_naive_utc_fromisoformat_date_only(self):
        # fromisoformat accepts plain dates; result is midnight, naive.
        self.assertEqual(
            naive_utc_fromisoformat("2026-01-02"),
            datetime(2026, 1, 2, 0, 0, 0),
        )

    def test_naive_utc_fromisoformat_invalid_raises(self):
        with self.assertRaises(ValueError):
            naive_utc_fromisoformat("not a datetime")
