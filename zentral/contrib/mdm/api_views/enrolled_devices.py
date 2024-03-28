from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.contrib.mdm.events import post_filevault_prk_viewed_event, post_recovery_password_viewed_event
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.serializers import EnrolledDeviceSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired


class EnrolledDeviceList(ListAPIView):
    queryset = EnrolledDevice.objects.all()
    serializer_class = EnrolledDeviceSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('udid', 'serial_number')


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
