from types import SimpleNamespace
from django.test import SimpleTestCase
from zentral.contrib.turbo.results import ResultsBatch
from zentral.core.compliance_checks.models import Status


class TurboResultsBatchTestCase(SimpleTestCase):
    @staticmethod
    def _parsed(kind, outcome, compliance_check_id=1):
        return SimpleNamespace(
            kind=kind, outcome=outcome, exit_code=outcome.get("exit_code"),
            definition=SimpleNamespace(compliance_check_id=compliance_check_id))

    def test_verdict_mscp_maps_wire_status(self):
        for code, expected in [(0, Status.OK), (200, Status.UNKNOWN),
                               (300, Status.FAILED), (400, Status.OUT_OF_SCOPE)]:
            self.assertEqual(ResultsBatch._verdict(self._parsed("mscp_check", {"status": code})), expected)

    def test_verdict_mscp_pending_and_unknown_codes_are_none(self):
        self.assertIsNone(ResultsBatch._verdict(self._parsed("mscp_check", {"status": Status.PENDING.value})))
        self.assertIsNone(ResultsBatch._verdict(self._parsed("mscp_check", {"status": 999})))

    def test_verdict_script_derives_from_exit_code(self):
        self.assertEqual(ResultsBatch._verdict(self._parsed("script", {"exit_code": 0})), Status.OK)
        self.assertEqual(ResultsBatch._verdict(self._parsed("script", {"exit_code": 1})), Status.FAILED)
        # couldn't run
        self.assertEqual(ResultsBatch._verdict(self._parsed("script", {"exit_code": None})), Status.UNKNOWN)

    def test_verdict_script_without_compliance_check_is_none(self):
        self.assertIsNone(ResultsBatch._verdict(self._parsed("script", {"exit_code": 0}, compliance_check_id=None)))

    def test_result_counts(self):
        batch = ResultsBatch("0123456789")
        batch.event_results = [{"kind": "script"}, {"kind": "script"}, {"kind": "mscp_check"}]
        self.assertEqual(batch.result_counts, {"script": 2, "mscp_check": 1})
