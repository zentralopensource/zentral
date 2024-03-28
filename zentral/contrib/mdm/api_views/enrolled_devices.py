from uuid import uuid4
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import EraseDevice, DeviceLock
from zentral.contrib.mdm.events import post_filevault_prk_viewed_event, post_recovery_password_viewed_event
from zentral.contrib.mdm.models import Channel, EnrolledDevice
from zentral.contrib.mdm.serializers import DeviceCommandSerializer, EnrolledDeviceSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired


class EnrolledDeviceList(ListAPIView):
    queryset = EnrolledDevice.objects.all()
    serializer_class = EnrolledDeviceSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('udid', 'serial_number')


class CreateEnrolledDeviceCommandView(APIView):
    permission_required = "mdm.add_devicecommand"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        if not self.command_class.verify_target(Target(enrolled_device)):
            return Response({"detail": "Invalid target."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.command_class.serializer_class(
            channel=Channel.DEVICE,
            enrolled_device=enrolled_device,
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        uuid = uuid4()
        command = self.command_class.create_for_device(
            enrolled_device,
            kwargs=serializer.get_command_kwargs(uuid),
            queue=True,
            uuid=uuid
        )
        cmd_serializer = DeviceCommandSerializer(command.db_command)
        return Response(cmd_serializer.data, status=status.HTTP_201_CREATED)


class EraseEnrolledDevice(CreateEnrolledDeviceCommandView):
    command_class = EraseDevice


class LockEnrolledDevice(CreateEnrolledDeviceCommandView):
    command_class = DeviceLock


class EnrolledDeviceFileVaultPRK(APIView):
    permission_required = "mdm.view_filevault_prk"
    permission_classes = [DjangoPermissionRequired]

    def get(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        filevault_prk = enrolled_device.get_filevault_prk()
        if filevault_prk:
            post_filevault_prk_viewed_event(request, enrolled_device)
        return Response({
            "id": enrolled_device.pk,
            "serial_number": enrolled_device.serial_number,
            "filevault_prk": filevault_prk,
        })


class EnrolledDeviceRecoveryPassword(APIView):
    permission_required = "mdm.view_recovery_password"
    permission_classes = [DjangoPermissionRequired]

    def get(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        recovery_password = enrolled_device.get_recovery_password()
        if recovery_password:
            post_recovery_password_viewed_event(request, enrolled_device)
        return Response({
            "id": enrolled_device.pk,
            "serial_number": enrolled_device.serial_number,
            "recovery_password": recovery_password,
        })
