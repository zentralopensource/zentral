from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework.views import APIView
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .models import Enrollment
from .osx_package.builder import MunkiZentralEnrollPkgBuilder
from .serializers import EnrollmentSerializer


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
        return builder.build_and_make_response()
