from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Configuration, Enrollment


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = ("id", "name", "description",
                  "inventory_apps_full_info_shard",
                  "principal_user_detection_sources", "principal_user_detection_domains",
                  "collected_condition_keys",
                  "managed_installs_sync_interval_days",
                  "auto_reinstall_incidents",
                  "auto_failed_install_incidents",
                  "version", "created_at", "updated_at")


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        fields = ("id", "configuration",
                  "secret", "version",
                  "enrolled_machines_count",
                  "package_download_url",
                  "created_at", "updated_at")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_package_download_url(self, obj):
        path = reverse("munki_api:enrollment_package", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'
