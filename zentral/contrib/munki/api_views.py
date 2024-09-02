from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.drf import (DefaultDjangoModelPermissions, DjangoPermissionRequired,
                               ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit)
from .models import Configuration, Enrollment, ScriptCheck
from .osx_package.builder import MunkiZentralEnrollPkgBuilder
from .serializers import ConfigurationSerializer, EnrollmentSerializer, ScriptCheckSerializer


# configurations


class ConfigurationList(ListCreateAPIViewWithAudit):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("name",)


class ConfigurationDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    permission_classes = [DefaultDjangoModelPermissions]


# enrollments


class EnrollmentList(generics.ListCreateAPIView):
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("configuration_id",)


class EnrollmentDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer


# enrollment packages


class EnrollmentPackage(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "munki.view_enrollment"
    permission_classes = [DjangoPermissionRequired]

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=self.kwargs["pk"])
        builder = MunkiZentralEnrollPkgBuilder(enrollment)
        return builder.get_conditional_response(self.request)


# script checks


class ScriptCheckFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="compliance_check__name")


class ScriptCheckList(ListCreateAPIViewWithAudit):
    queryset = ScriptCheck.objects.select_related("compliance_check").all()
    serializer_class = ScriptCheckSerializer
    filterset_class = ScriptCheckFilter


class ScriptCheckDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ScriptCheck.objects.select_related("compliance_check").all()
    serializer_class = ScriptCheckSerializer
