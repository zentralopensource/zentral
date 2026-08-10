from django.contrib.postgres.fields import ArrayField
from django.db import models


class WatchState(models.Model):
    """What a watch last concluded about one subject.

    Sparse: only currently degraded subjects have a row, so "no row" is the healthy state. The row
    carries both sides of the last transition, which is what lets change detection run in the database
    without anything stored to diff against — the same shape as MachineStatus.previous_status.
    """
    watch = models.CharField(max_length=256)
    # opaque: the pk of the watched row, or a composite key. Never a FK — a watch's subject may live in
    # any module, or be a tuple of pks, and core must not learn about either.
    subject_id = models.TextField()
    # only set when the subject IS a machine. Decides MachineIncident vs Incident downstream, and lets a
    # machine's watch state be found without knowing each watch's subject encoding.
    serial_number = models.TextField(null=True, db_index=True)
    # ALWAYS SORTED, both of them: `reasons IS DISTINCT FROM` compares arrays element-wise *ordered*, so
    # an unsorted array re-fires on every reordering.
    reasons = ArrayField(models.CharField(max_length=256))
    previous_reasons = ArrayField(models.CharField(max_length=256), default=list)
    # max over `reasons`; null when the watch opens no incident
    severity = models.PositiveSmallIntegerField(null=True)
    # The key of the incident this row opened, captured on INSERT and never updated afterwards, so it
    # stays pinned to the incident that was actually opened. Closing is an exact jsonb match on
    # Incident.key and a miss is silent, so the key has to be stored rather than rebuilt: a subject may
    # be gone by then, and a rebuild that drifts by so much as an int-vs-string closes nothing and says
    # nothing. jsonb because the incident key is itself composite for several incident types.
    incident_key = models.JSONField(null=True)
    first_fired_at = models.DateTimeField()   # set on insert, never updated: how long it has been bad
    fired_at = models.DateTimeField()         # last transition

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["watch", "subject_id"], name="watchers_watchstate_unique"),
        ]

    def __str__(self):
        return f"{self.watch} {self.subject_id}"
