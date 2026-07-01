import io

from django.db.models import Count
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.drf import (DjangoPermissionRequired, ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination, RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Enrollment
from ..serializers import EnrollmentSerializer
from ..utils import build_configuration_plist, build_configuration_profile


class EnrollmentList(ListCreateAPIViewWithAudit):
    queryset = Enrollment.objects.annotate(enrolled_machines_count=Count("enrolledmachine"))
    serializer_class = EnrollmentSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration",)


class EnrollmentDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Enrollment.objects.annotate(enrolled_machines_count=Count("enrolledmachine"))
    serializer_class = EnrollmentSerializer

    def perform_update(self, serializer):
        if not serializer.instance.can_be_updated():
            raise ValidationError("This enrollment cannot be updated")
        return super().perform_update(serializer)

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This enrollment cannot be deleted")
        return super().perform_destroy(instance)


class EnrollmentConfiguration(APIView):
    """
    base enrollment configuration class. To be subclassed.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "turbo.view_enrollment"
    permission_classes = [DjangoPermissionRequired]

    def get_content(self, enrollment):
        raise NotImplementedError

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"])
        filename, content_type, content = self.get_content(enrollment)
        return FileResponse(io.BytesIO(content), as_attachment=True,
                            filename=filename, content_type=content_type)


class EnrollmentPlist(EnrollmentConfiguration):
    """
    Download enrollment plist file
    """

    def get_content(self, enrollment):
        filename, content = build_configuration_plist(enrollment)
        return filename, "application/x-plist", content


class EnrollmentConfigurationProfile(EnrollmentConfiguration):
    """
    Download enrollment configuration profile
    """

    def get_content(self, enrollment):
        filename, content = build_configuration_profile(enrollment)
        return filename, "application/octet-stream", content
