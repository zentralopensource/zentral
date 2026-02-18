from datetime import timedelta
import functools
import operator

from django.contrib.auth.models import Permission
from django.db.models import Q

from rest_framework import serializers

from .models import Group, ProvisionedRole, User


class RoleSerializer(serializers.ModelSerializer):
    permissions = serializers.ListField(child=serializers.CharField(min_length=1), required=False)

    class Meta:
        model = Group
        fields = (
            "name",
            "permissions",
        )

    def validate(self, data):
        data_permissions = data.pop("permissions", [])
        data = super().validate(data)
        permission_filters = []
        if data_permissions:
            for data_permission in data_permissions:
                try:
                    app_label, codename = data_permission.split(".", 1)
                except ValueError:
                    pass
                permission_filters.append(Q(content_type__app_label=app_label, codename=codename))
        if permission_filters:
            data["permissions"] = Permission.objects.filter(functools.reduce(operator.or_, permission_filters))
        else:
            data["permissions"] = []
        return data

    def create(self, validated_data):
        provisioning_uid = validated_data.pop("provisioning_uid", None)
        role = super().create(validated_data)
        if provisioning_uid:
            ProvisionedRole.objects.create(group=role, provisioning_uid=provisioning_uid)
        return role


class OIDCAPITokenExchangeInputSerializer(serializers.Serializer):
    jwt = serializers.CharField()
    name = serializers.CharField(required=False, allow_blank=True, max_length=256)
    duration = serializers.IntegerField(required=False, min_value=1)

    def get_duration(self, max_duration: timedelta) -> timedelta:
        seconds = self.validated_data.get("duration")
        if seconds is None:
            return max_duration
        requested = timedelta(seconds=seconds)
        return min(requested, max_duration)

    def get_name(self, default_name: str) -> str:
        name = self.validated_data.get("name")
        if name is None:
            return default_name
        name = name.strip()
        return name or default_name


class SimpleUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email")


class APITokenWithSecretSerializer(serializers.Serializer):
    pk = serializers.UUIDField(read_only=True)
    name = serializers.CharField(read_only=True)
    expiry = serializers.DateTimeField(read_only=True)
    secret = serializers.CharField(read_only=True)


class OIDCAPITokenExchangeResponseSerializer(serializers.Serializer):
    user = SimpleUserSerializer()
    token = APITokenWithSecretSerializer()
