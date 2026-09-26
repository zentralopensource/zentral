from rest_framework import serializers


class LDAPConfigSerializer(serializers.Serializer):
    host = serializers.CharField()
    bind_dn = serializers.CharField()
    bind_password = serializers.CharField(write_only=True)
    users_base_dn = serializers.CharField()
