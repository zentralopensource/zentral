from rest_framework import serializers


class EventFilterSerializer(serializers.Serializer):
    tags = serializers.ListField(
        child=serializers.CharField(min_length=1),
        allow_empty=True,
        required=False,
    )
    event_type = serializers.ListField(
        child=serializers.CharField(min_length=1),
        allow_empty=True,
        required=False,
    )
    routing_key = serializers.ListField(
        child=serializers.CharField(min_length=1),
        allow_empty=True,
        required=False,
    )


class EventFilterSetSerializer(serializers.Serializer):
    excluded_event_filters = EventFilterSerializer(many=True, required=False)
    included_event_filters = EventFilterSerializer(many=True, required=False)
