from rest_framework import serializers
from .models import Blueprint


class BlueprintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blueprint
        exclude = ["serialized_artifacts"]
