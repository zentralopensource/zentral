from rest_framework import serializers


class OpenIDCConfigSerializer(serializers.Serializer):
    discovery_url = serializers.URLField()
    client_id = serializers.CharField()
    client_secret = serializers.CharField(required=False)
    extra_scopes = serializers.ListField(
        child=serializers.CharField(min_length=1),
        allow_empty=True,
        default=list
    )
