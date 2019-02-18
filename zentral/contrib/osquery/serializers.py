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

    class Meta:
        model = Enrollment
        # TODO: distributor, maybe with a link ?
        fields = ("id", "configuration", "osquery_release", "secret", "version")

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret = EnrollmentSecret.objects.create(**secret_data)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment
