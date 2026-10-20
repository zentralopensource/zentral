from rest_framework import serializers
from .models import ComplianceCheck, MachineStatus, Status


class StatusField(serializers.Field):
    def to_representation(self, value):
        return Status(value).name


class ComplianceCheckSerializer(serializers.ModelSerializer):
    status_counts = serializers.DictField(child=serializers.IntegerField(), read_only=True)
    outdated_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = ComplianceCheck
        fields = (
            "id",
            "model",
            "name",
            "description",
            "version",
            "status_counts",
            "outdated_count",
            "created_at",
            "updated_at",
        )


class MachineStatusSerializer(serializers.ModelSerializer):
    status = StatusField(read_only=True)
    previous_status = StatusField(read_only=True)

    class Meta:
        model = MachineStatus
        fields = (
            "id",
            "compliance_check",
            "compliance_check_version",
            "serial_number",
            "status",
            "status_time",
            "previous_status",
        )
