import logging
from rest_framework import serializers
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping
from zentral.contrib.google_workspace.api_client import APIClient, validate_group_in_connection


logger = logging.getLogger('zentral.contrib.google_workspace.serializers')


class ConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Connection
        fields = [
            "id",
            "name",
            "created_at",
            "updated_at",
        ]


class ConnectionDetailSerializer(ConnectionSerializer):
    healthy = serializers.SerializerMethodField()

    def get_healthy(self, connection):
        api_client = APIClient.from_connection(connection)
        return api_client.is_healthy()

    class Meta:
        model = Connection
        fields = ConnectionSerializer.Meta.fields + ["healthy"]

        read_only_fields = (
            "healthy",
        )


class GroupTagMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupTagMapping
        fields = (
            "id",
            "group_email",
            "connection",
            "tags",
            "created_at",
            "updated_at",
        )

    def validate(self, attrs):
        data = super().validate(attrs)
        group_email = data.get("group_email")
        connection = data.get("connection")
        validate_group_in_connection(connection, group_email,
                                     error_supplier=lambda: serializers.ValidationError(
                                               {"group_email": "Group email not found for this connection."}))

        return data
