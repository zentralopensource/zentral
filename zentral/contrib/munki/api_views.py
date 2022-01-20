from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework.views import APIView
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .models import Configuration, Enrollment
from .osx_package.builder import MunkiZentralEnrollPkgBuilder
from .serializers import ConfigurationSerializer, EnrollmentSerializer


class ConfigurationList(generics.ListAPIView):
    """
    List all Configurations
    """
    queryset = Configuration.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationSerializer


class ConfigurationDetail(generics.RetrieveAPIView):
    """
    Retrieve a Configuration instance.
    """
    queryset = Configuration.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationSerializer


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
