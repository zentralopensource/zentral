from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Enrollment


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        fields = ("id", "configuration",
                  "secret", "version",
                  "enrolled_machines_count",
                  "package_download_url")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_package_download_url(self, obj):
        path = reverse("munki_api:enrollment_package", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'
