from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Configuration, Enrollment


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        instance.refresh_from_db()
        return instance


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        exclude = ("distributor_content_type", "distributor_pk")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_package_download_url(self, obj):
        path = reverse("munki_api:enrollment_package", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret_tags = secret_data.pop("tags", [])
        secret = EnrollmentSecret.objects.create(**secret_data)
        if secret_tags:
            secret.tags.set(secret_tags)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment

    def update(self, instance, validated_data):
        secret_serializer = self.fields["secret"]
        secret_data = validated_data.pop('secret')
        secret_serializer.update(instance.secret, secret_data)
        return super().update(instance, validated_data)
