import logging

from zentral.core.incidents.models import Severity
from zentral.core.watchers import register_watch
from zentral.core.watchers.watches import BaseWatch

from .events import PushCertificateHealthEvent
from .incidents import PushCertificateExpiryIncident


logger = logging.getLogger("zentral.contrib.mdm.watches")


class PushCertificateExpiryWatch(BaseWatch):
    """The APNs push certificate is running out.

    Nothing warns on this today, and it is the one failure here that cannot be recovered from by waiting:
    once the certificate expires every device becomes unmanageable at once, and renewal needs a CSR and
    Apple portal access. Hence the long lead time — 90 days, where a DEP token would want a week.
    """
    name = "mdm_push_certificate_expiry"
    interval = 3600   # a handful of rows and deadlines measured in days: hourly is ample
    incident_class = PushCertificateExpiryIncident
    event_class = PushCertificateHealthEvent
    # one certificate serves the whole fleet, so the incident is not a machine's — see the class
    # docstring. Left explicit because the other two watches are machine scoped.
    machine_scoped = False

    # ONE source of truth for the ladder, most urgent first — both SQL CASEs are generated from it, so a
    # reason and its severity cannot drift apart. Severity only ever ratchets up (open_incident never
    # lowers it), which is exactly the shape of a deadline approaching.
    ladder = (
        ("expired", 0, Severity.CRITICAL),
        ("expiring_7d", 7 * 86400, Severity.CRITICAL),
        ("expiring_30d", 30 * 86400, Severity.MAJOR),
        ("expiring_90d", 90 * 86400, Severity.MINOR),
    )

    @property
    def severities(self):
        return {reason: severity.value for reason, _, severity in self.ladder}

    def _cases(self):
        # first WHEN wins, and the bands are ordered most urgent first, so the reasons are mutually
        # exclusive by construction — the array is always length one
        reason_case = severity_case = ""
        for reason, _, severity in self.ladder:
            condition = f"pc.not_after <= NOW() + interval '1 second' * %({reason}_offset)s"
            reason_case += f"WHEN {condition} THEN '{reason}' "
            severity_case += f"WHEN {condition} THEN {severity.value} "
        return f"CASE {reason_case}END", f"CASE {severity_case}END"

    @property
    def degraded_select(self):
        reason_case, severity_case = self._cases()
        widest = self.ladder[-1][0]
        return (
            f"SELECT %(watch)s, pc.id::text, NULL, ARRAY[{reason_case}], ARRAY[]::varchar[],"
            f"       {severity_case}, jsonb_build_object('mdm_pc_pk', pc.id), NOW(), NOW() "
            "  FROM mdm_pushcertificate AS pc"
            # a push certificate without one is not provisioned yet: nothing to warn about
            " WHERE pc.not_after IS NOT NULL"
            f"   AND pc.not_after <= NOW() + interval '1 second' * %({widest}_offset)s"
        )

    # The cast goes on the ws side, never on pc.id. A handful of rows makes the direction free here,
    # which is the reason to write it the same way as everywhere else rather than to decide it per watch.
    _MATCH_SUBJECT = "pc.id = ws.subject_id::integer"

    @property
    def still_degraded(self):
        widest = self.ladder[-1][0]
        return (
            "SELECT 1 FROM mdm_pushcertificate AS pc"
            f" WHERE {self._MATCH_SUBJECT} AND pc.not_after IS NOT NULL"
            f"   AND pc.not_after <= NOW() + interval '1 second' * %({widest}_offset)s"
        )

    subject_alive = f"SELECT 1 FROM mdm_pushcertificate AS pc WHERE {_MATCH_SUBJECT}"

    def get_query_kwargs(self):
        kwargs = super().get_query_kwargs()
        for reason, offset, _ in self.ladder:
            kwargs[f"{reason}_offset"] = offset
        return kwargs

    @staticmethod
    def get_subjects(rows):
        """The certificate behind each row, in one query — a per-row lookup would be N+1.

        The model owns the payload shape: a cleared not_after serializes to None on its own, which is one
        of the ways a certificate leaves the watch.
        """
        from .models import PushCertificate
        subject_ids = {row.subject_id for row in rows}
        if not subject_ids:
            return {}
        return {
            str(push_certificate.pk): push_certificate.serialize_for_event()
            for push_certificate in PushCertificate.objects.filter(pk__in=subject_ids)
        }

    def get_payload(self, row, subject):
        # subject is None when a concurrent delete lands between the statements and the lookup — the
        # transition still happened, and the incident update comes from the row, so the event still goes
        return {"push_certificate": subject}


register_watch(PushCertificateExpiryWatch)
