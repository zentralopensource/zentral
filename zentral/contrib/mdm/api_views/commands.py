from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView, RetrieveAPIView, RetrieveDestroyAPIView
from django.db import transaction
from rest_framework.authentication import SessionAuthentication
from accounts.api_authentication import APITokenAuthentication

from zentral.contrib.mdm.models import DeviceCommand, UserCommand
from zentral.contrib.mdm.serializers import DeviceCommandSerializer, UserCommandSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions, MaxLimitOffsetPagination
from zentral.core.events.base import AuditEvent


class EnrolledDeviceCommandList(ListAPIView):
    queryset = DeviceCommand.objects.all().order_by("-created_at")
    serializer_class = DeviceCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name', 'enrolled_device')
    pagination_class = MaxLimitOffsetPagination


class EnrolledDeviceCommand(RetrieveDestroyAPIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    queryset = DeviceCommand.objects.all()
    serializer_class = DeviceCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    lookup_field = "uuid"

    def perform_destroy(self, instance):
        command = DeviceCommand.objects.select_for_update().get(pk=instance.pk)
        if not command.can_be_deleted():
            raise ValidationError("This command has already been sent to the device and cannot be deleted")
        prev_value = command.serialize_for_event()
        prev_pk = command.pk
        command.delete()

        def on_commit_callback():
            command.pk = prev_pk  # re-hydrate the primary key
            AuditEvent.build_from_request_and_instance(
                self.request, command,
                action=AuditEvent.Action.DELETED,
                prev_value=prev_value,
            ).post()

        transaction.on_commit(on_commit_callback)


class EnrolledUserCommandList(ListAPIView):
    queryset = UserCommand.objects.all().order_by("-created_at")
    serializer_class = UserCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name', 'enrolled_user')
    pagination_class = MaxLimitOffsetPagination


class EnrolledUserCommand(RetrieveAPIView):
    queryset = UserCommand.objects.all()
    serializer_class = UserCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    lookup_field = "uuid"
