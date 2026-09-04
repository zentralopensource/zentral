from rest_framework import serializers

from .models import ScheduleMode

# The agent ↔ server wire contract, as declarative serializers. Validation is strict per entry,
# tolerant per batch: a body that does not match its envelope is a 400, but a results/status entry
# that does not match the wire schema is set aside (rejected) while the valid entries are processed —
# a wholesale 4xx would just make the agent retry the same poisoned outbox forever. The response
# acknowledges every processed entry (accepted / skipped), so the agent can deduce the rejected ones.

# upper bound of the ledger's PositiveIntegerField columns
UINT_MAX = 2**31 - 1


class TolerantListSerializer(serializers.ListSerializer):
    # an entry either validates or is set aside in .rejected — the valid entries still come through
    rejected = ()

    def to_internal_value(self, data):
        if not isinstance(data, list):
            self.fail("not_a_list", input_type=type(data).__name__)
        entries = []
        self.rejected = []
        for index, item in enumerate(data):
            try:
                entries.append(self.child.run_validation(item))
            except serializers.ValidationError as e:
                self.rejected.append({"index": index, "errors": e.detail})
        return entries


class WireEnrollSerializer(serializers.Serializer):
    # bounds are over-provisioned, not exact: a real serial is ~12-20 chars and a hardware UUID is 36.
    # secret matches EnrollmentSecret.secret (max_length 256) — a longer value cannot match one anyway
    secret = serializers.CharField(max_length=256)
    serial_number = serializers.CharField(max_length=256)
    hardware_uuid = serializers.CharField(max_length=64)


class WireScheduleSerializer(serializers.Serializer):
    # the plan echoed back by the agent in a status entry (config serves the same shape)
    mode = serializers.ChoiceField(choices=ScheduleMode.values, required=False)
    pk = serializers.UUIDField()
    interval = serializers.IntegerField(required=False, allow_null=True, default=None,
                                        min_value=0, max_value=UINT_MAX)


class WireRunSerializer(serializers.Serializer):
    # one realized execution, in a results entry. `at` is required — a result the server cannot
    # time-stamp cannot be scored or close a one-time gate, so the whole entry is rejected. `mode` is
    # informational — correlation is by schedule_pk alone.
    at = serializers.DateTimeField()
    duration = serializers.FloatField(required=False, allow_null=True, default=None)
    schedule_pk = serializers.UUIDField()
    mode = serializers.ChoiceField(choices=ScheduleMode.values, required=False)


class WireResultSerializer(serializers.Serializer):
    # one results[] entry: the §5 identity block + run + outcome. kind/pk/version are declarative —
    # the resolved schedule stays authoritative — so they only need to be well-formed when present.
    #
    # kind is NOT a choice over Job.Kind: during a rollout the instances do not share a set of kinds,
    # and an entry naming a kind this one has not learned yet is a well-formed report of a run that
    # happened, not a malformed entry. Rejecting it drops it whole — no acknowledgment for the agent
    # to read, and the shot never closes. Accepted as a short string, it reaches the view, where the
    # resolved job decides (unknown_job_kind / kind_mismatch). max_length matches Job.kind's column.
    kind = serializers.CharField(max_length=32, required=False, allow_null=True, default=None)
    pk = serializers.UUIDField(required=False, allow_null=True, default=None)
    version = serializers.IntegerField(required=False, allow_null=True, default=None,
                                       min_value=0, max_value=UINT_MAX)
    run = WireRunSerializer()
    result = serializers.DictField(required=False, default=dict)

    class Meta:
        list_serializer_class = TolerantListSerializer

    def validate_result(self, value):
        # the outcome dict stays open (room for future fields like result.error), but the two fields
        # the server scores on must be well-typed. exit_code: process exit code, or null = couldn't run.
        exit_code = value.get("exit_code")
        if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
            raise serializers.ValidationError("exit_code must be an integer or null")
        status = value.get("status")
        if status is not None and (isinstance(status, bool) or not isinstance(status, int)):
            raise serializers.ValidationError("status must be an integer")
        return value


class WireStatusEntrySerializer(serializers.Serializer):
    # one status jobs[] entry: the identity block + the held schedule + last_run (event-only, so it
    # stays an open dict)
    #
    # kind is a short string and not a choice, for the reason WireResultSerializer gives: an entry
    # naming a kind this instance has not learned yet is what a rollout looks like. Here it is purely
    # declarative — nothing reads it, the resolved job carries the authoritative kind — so the only
    # thing a choice bought was dropping the entry, and with it the tracker update that keeps a job
    # the agent still holds from being swept as removed.
    kind = serializers.CharField(max_length=32, required=False, allow_null=True, default=None)
    pk = serializers.UUIDField(required=False, allow_null=True, default=None)
    version = serializers.IntegerField(required=False, allow_null=True, default=None,
                                       min_value=0, max_value=UINT_MAX)
    schedule = WireScheduleSerializer()
    last_run = serializers.DictField(required=False, allow_null=True, default=None)

    class Meta:
        list_serializer_class = TolerantListSerializer


class BaseWireBodySerializer(serializers.Serializer):
    # a POST body envelope with one tolerant list; `rejected` surfaces the set-aside entries for the
    # view's log line (the agent deduces them from the acknowledged accepted/skipped lists)
    entries_key = None

    @property
    def rejected(self):
        return getattr(self.fields[self.entries_key], "rejected", ())


class WireResultsSerializer(BaseWireBodySerializer):
    entries_key = "results"
    results = WireResultSerializer(many=True, required=False, default=list)


class WireStatusSerializer(BaseWireBodySerializer):
    entries_key = "jobs"
    jobs = WireStatusEntrySerializer(many=True, required=False, default=list)
