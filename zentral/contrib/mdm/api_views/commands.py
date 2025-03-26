from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView, RetrieveAPIView
from zentral.contrib.mdm.models import DeviceCommand, UserCommand
from zentral.contrib.mdm.serializers import DeviceCommandSerializer, UserCommandSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions, MaxLimitOffsetPagination


class EnrolledDeviceCommandList(ListAPIView):
    queryset = DeviceCommand.objects.all().order_by("-created_at")
    serializer_class = DeviceCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name', 'enrolled_device')
    pagination_class = MaxLimitOffsetPagination


class EnrolledDeviceCommand(RetrieveAPIView):
    queryset = DeviceCommand.objects.all()
    serializer_class = DeviceCommandSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    lookup_field = "uuid"


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
