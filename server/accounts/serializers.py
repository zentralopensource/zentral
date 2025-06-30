import functools
import operator
from django.contrib.auth.models import Permission
from django.db.models import Q
from rest_framework import serializers
from .models import Group, ProvisionedRole


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
