from uuid import uuid4
from django.db.models import Exists, OuterRef, JSONField
from django.db.models.expressions import RawSQL
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.api_authentication import APITokenAuthentication
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import CustomCommand, EraseDevice, DeviceLock
from zentral.contrib.mdm.events import post_filevault_prk_viewed_event, post_recovery_password_viewed_event
from zentral.contrib.mdm.models import Channel, EnrolledDevice
from zentral.contrib.mdm.serializers import (DeviceCommandSerializer,
                                             EnrolledDeviceSerializer, EnrolledDeviceAdminPasswordSerializer)
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired, MaxLimitOffsetPagination


class EnrolledDeviceFilter(filters.FilterSet):
    tags = filters.ModelMultipleChoiceFilter(
        field_name="id",
        to_field_name="id",
        queryset=Tag.objects.all(),
        method="filter_tags",
    )
    excluded_tags = filters.ModelMultipleChoiceFilter(
        field_name="id",
        to_field_name="id",
        queryset=Tag.objects.all(),
        method="filter_excluded_tags",
    )
    short_name = filters.CharFilter(
        field_name="users__short_name",
        lookup_expr="icontains",
        method="filter_short_name",
    )
    email = filters.CharFilter(
        method="filter_email",
    )

    def filter_tags(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Exists(
                MachineTag.objects.filter(
                    serial_number=OuterRef("serial_number"),
                    tag__in=value
                )
            )
        )

    def filter_excluded_tags(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            ~Exists(
                MachineTag.objects.filter(
                    serial_number=OuterRef("serial_number"),
                    tag__in=value
                )
            )
        )

    def filter_short_name(self, queryset, _, value):
        if not value:
            return queryset
        return queryset.filter(users__short_name__exact=value)

    def filter_email(self, queryset, _, value):
        if not value:
            return queryset
        return queryset.filter(realm_user__email=value)

    class Meta:
        model = EnrolledDevice
        fields = ["udid", "serial_number", "tags", "excluded_tags", "short_name", "email"]


class EnrolledDeviceList(ListAPIView):
    # Using RawSQL as the simplest solution to add the realm user to the enrolled device list.
    # Using QuerySet.union() will lead to ValuesQuerySet which do not work with the ModelSerializer of this view.
    # Using QUerySet.subqueries will lead to the problem to decide on a non key field which enrollment to use.
    queryset = (
        EnrolledDevice.objects
        .prefetch_related("users")
        .annotate(
            realm_user=RawSQL(
                f"""
                SELECT json_build_object(
                    'pk', u.uuid,
                    'username', u.username,
                    'email', u.email
                )::jsonb
                FROM (
                    SELECT enrolled_device_id, realm_user_id, created_at
                    FROM mdm_depenrollmentsession WHERE realm_user_id IS NOT NULL
                    UNION ALL
                    SELECT enrolled_device_id, realm_user_id, created_at
                    FROM mdm_otaenrollmentsession WHERE realm_user_id IS NOT NULL
                    UNION ALL
                    SELECT enrolled_device_id, realm_user_id, created_at
                    FROM mdm_reenrollmentsession WHERE realm_user_id IS NOT NULL
                    UNION ALL
                    SELECT enrolled_device_id, realm_user_id, created_at
                    FROM mdm_userenrollmentsession WHERE realm_user_id IS NOT NULL
                ) s
                JOIN realms_realmuser u ON u.uuid = s.realm_user_id
                WHERE s.enrolled_device_id = {EnrolledDevice._meta.db_table}.{EnrolledDevice._meta.pk.column}
                ORDER BY s.created_at DESC
                LIMIT 1
                """,
                [],
                output_field=JSONField(),
            )
        )
    )
    serializer_class = EnrolledDeviceSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = EnrolledDeviceFilter
    ordering_fields = ('created_at', 'last_seen_at', 'updated_at')
    ordering = ['-created_at']
    pagination_class = MaxLimitOffsetPagination


class BlockEnrolledDevice(APIView):
    permission_required = "mdm.change_enrolleddevice"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        if enrolled_device.blocked_at:
            return Response({"detail": "Device already blocked."}, status=status.HTTP_400_BAD_REQUEST)
        enrolled_device.block()
        enrolled_device.refresh_from_db()
        serializer = EnrolledDeviceSerializer(enrolled_device)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UnblockEnrolledDevice(APIView):
    permission_required = "mdm.change_enrolleddevice"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        enrolled_device = get_object_or_404(EnrolledDevice, pk=kwargs["pk"])
        if not enrolled_device.blocked_at:
            return Response({"detail": "Device not blocked."}, status=status.HTTP_400_BAD_REQUEST)
        enrolled_device.unblock()
        enrolled_device.refresh_from_db()
        serializer = EnrolledDeviceSerializer(enrolled_device)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
        serializer = DeviceCommandSerializer(command.db_command)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class EraseEnrolledDevice(CreateEnrolledDeviceCommandView):
    command_class = EraseDevice


class LockEnrolledDevice(CreateEnrolledDeviceCommandView):
    command_class = DeviceLock


class SendCustomEnrolledDeviceCommand(CreateEnrolledDeviceCommandView):
    command_class = CustomCommand


class EnrolledDeviceAdminPassword(RetrieveAPIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "mdm.view_admin_password"
    permission_classes = [DjangoPermissionRequired]
    serializer_class = EnrolledDeviceAdminPasswordSerializer
    queryset = EnrolledDevice.objects.all()


class EnrolledDeviceFileVaultPRK(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
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
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
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
