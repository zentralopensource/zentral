from rest_framework import serializers
from .models import Manifest


class ManifestSerializer(serializers.ModelSerializer):

    class Meta:
        model = Manifest
        fields = '__all__'
