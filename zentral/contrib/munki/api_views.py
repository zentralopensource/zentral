from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.views import APIView
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .models import Configuration, Enrollment
from .osx_package.builder import MunkiZentralEnrollPkgBuilder
from .serializers import ConfigurationSerializer, EnrollmentSerializer


# configurations


class ConfigurationList(generics.ListCreateAPIView):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("name",)


class ConfigurationDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    permission_classes = [DefaultDjangoModelPermissions]


# enrollments


class EnrollmentList(generics.ListAPIView):
    """
    List all Enrollments
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer


class EnrollmentDetail(generics.RetrieveAPIView):
    """
    Retrieve an Enrollment instance.
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer


class EnrollmentPackage(APIView):
    """
    Download enrollment package
    """
    permission_required = "munki.view_enrollment"
    permission_classes = [DjangoPermissionRequired]

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=self.kwargs["pk"])
        builder = MunkiZentralEnrollPkgBuilder(enrollment)
        return builder.get_conditional_response(self.request)
