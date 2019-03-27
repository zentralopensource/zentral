from rest_framework import serializers
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Configuration, Enrollment


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = ("id", "name",
                  "config_refresh", "distributed_interval",
                  "disable_carver", "buffered_log_max")


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        # TODO: distributor, maybe with a link ?
        fields = ("id", "configuration", "enrolled_machines_count", "osquery_release", "secret", "version")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret = EnrollmentSecret.objects.create(**secret_data)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment

    def update(self, instance, validated_data):
        secret_serializer = self.fields["secret"]
        secret_data = validated_data.pop('secret')
        secret_serializer.update(instance.secret, secret_data)
        return super().update(instance, validated_data)
