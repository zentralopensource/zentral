from rest_framework import serializers


class SAMLConfigSerializer(serializers.Serializer):
    default_relay_state = serializers.UUIDField(required=False)
    idp_metadata = serializers.CharField()
