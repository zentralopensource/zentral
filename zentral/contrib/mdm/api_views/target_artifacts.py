from django.db import transaction
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.mdm.apns import send_enrolled_device_notification, send_enrolled_user_notification
from zentral.contrib.mdm.artifacts import ForceArtifactInstallError, Target
from zentral.contrib.mdm.models import (
    Artifact,
    Channel,
    DeviceArtifact,
    EnrolledDevice,
    EnrolledUser,
    TargetArtifact,
    UserArtifact,
)
from zentral.contrib.mdm.pbac import ForceInstallArtifactRequest
from zentral.contrib.mdm.serializers import DeviceArtifactSerializer, UserArtifactSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions, MaxLimitOffsetPagination, PBACPermission


class BaseTargetArtifactFilter(filters.FilterSet):
    artifact = filters.ModelChoiceFilter(
        field_name="artifact_version__artifact",
        queryset=Artifact.objects.all(),
    )
    status = filters.ChoiceFilter(choices=TargetArtifact.Status.choices)
    force_install_requested = filters.BooleanFilter(
        field_name="force_install_requested_at",
        lookup_expr="isnull",
        exclude=True,
    )


class DeviceArtifactFilter(BaseTargetArtifactFilter):
    enrolled_device = filters.ModelChoiceFilter(queryset=EnrolledDevice.objects.all())


class UserArtifactFilter(BaseTargetArtifactFilter):
    enrolled_user = filters.ModelChoiceFilter(queryset=EnrolledUser.objects.all())


class BaseTargetArtifactList(ListAPIView):
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    pagination_class = MaxLimitOffsetPagination


class EnrolledDeviceArtifactList(BaseTargetArtifactList):
    """
    List the target artifacts of the enrolled devices.
    """
    # LIMIT/OFFSET pagination is only stable on a total order, and updated_at is not
    # unique: the primary key breaks the ties.
    queryset = (DeviceArtifact.objects.select_related("artifact_version__artifact")
                                      .order_by("-updated_at", "-pk"))
    serializer_class = DeviceArtifactSerializer
    filterset_class = DeviceArtifactFilter


class EnrolledUserArtifactList(BaseTargetArtifactList):
    """
    List the target artifacts of the enrolled users.
    """
    queryset = (UserArtifact.objects.select_related("artifact_version__artifact")
                                    .order_by("-updated_at", "-pk"))
    serializer_class = UserArtifactSerializer
    filterset_class = UserArtifactFilter


class BaseForceInstallArtifact(APIView):
    permission_classes = [PBACPermission]

    def get_pbac_request(self, request):
        self.load_target_objects()
        self.artifact = get_object_or_404(Artifact, pk=self.kwargs["artifact_pk"])
        return ForceInstallArtifactRequest(
            request.user,
            MetaMachine(self.enrolled_device.serial_number),
            self.artifact,
            self.channel,
        )

    def post(self, request, *args, **kwargs):
        target = Target(self.enrolled_device, self.enrolled_user)
        try:
            target_artifact, deleted_command_count = target.force_artifact_install(self.artifact, request)
        except ForceArtifactInstallError as error:
            return Response({"detail": str(error)}, status=status.HTTP_400_BAD_REQUEST)
        if self.enrolled_user:
            enrolled_user = self.enrolled_user
            transaction.on_commit(lambda: send_enrolled_user_notification(enrolled_user, request=request))
        else:
            enrolled_device = self.enrolled_device
            transaction.on_commit(lambda: send_enrolled_device_notification(enrolled_device, request=request))
        serializer = self.serializer_class(target_artifact)
        return Response({"target_artifact": serializer.data,
                         "deleted_command_count": deleted_command_count})


class ForceInstallEnrolledDeviceArtifact(BaseForceInstallArtifact):
    """
    Force the install of an artifact on an enrolled device.
    """
    channel = Channel.DEVICE
    serializer_class = DeviceArtifactSerializer

    def load_target_objects(self):
        self.enrolled_device = get_object_or_404(EnrolledDevice, pk=self.kwargs["pk"])
        self.enrolled_user = None


class ForceInstallEnrolledUserArtifact(BaseForceInstallArtifact):
    """
    Force the install of an artifact on an enrolled user.
    """
    channel = Channel.USER
    serializer_class = UserArtifactSerializer

    def load_target_objects(self):
        self.enrolled_user = get_object_or_404(
            EnrolledUser.objects.select_related("enrolled_device__push_certificate"),
            pk=self.kwargs["pk"],
        )
        self.enrolled_device = self.enrolled_user.enrolled_device
