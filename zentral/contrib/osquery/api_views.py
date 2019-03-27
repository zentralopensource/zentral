from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from .models import Configuration, Enrollment
from .serializers import ConfigurationSerializer, EnrollmentSerializer


class ConfigurationList(generics.ListCreateAPIView):
    """
    List all Configurations, search Configuration by name, or create a new Configuration.
    """
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class ConfigurationDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a Configuration instance.
    """
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This configuration cannot be deleted')
        else:
            return super().perform_destroy(instance)


class EnrollmentList(generics.ListCreateAPIView):
    """
    List all Enrollments or create a new Enrollment
    """
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer


class EnrollmentDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete an Enrollment instance.
    """
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This enrollment cannot be deleted')
        else:
            return super().perform_destroy(instance)
