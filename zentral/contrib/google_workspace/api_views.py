import logging
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django_filters import rest_framework as filters
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.drf import DjangoPermissionRequired, DefaultDjangoModelPermissions
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping
from zentral.contrib.google_workspace.serializers import (
    ConnectionSerializer,
    GroupTagMappingSerializer,
    ConnectionDetailSerializer
)
from zentral.contrib.google_workspace.tasks import sync_group_tag_mappings_task
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit


logger = logging.getLogger('zentral.contrib.google_workspace.api_views')


class SyncTagsView(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "google_workspace.view_connection"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        connection = get_object_or_404(Connection, pk=kwargs["conn_pk"])
        result = sync_group_tag_mappings_task.apply_async((connection.pk,))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class ConnectionList(ListAPIView):
    queryset = Connection.objects.all()
    serializer_class = ConnectionSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class ConnectionDetail(RetrieveAPIView):
    queryset = Connection.objects.all()
    serializer_class = ConnectionDetailSerializer
    permission_classes = [DefaultDjangoModelPermissions]


class GroupTagMappingList(ListCreateAPIViewWithAudit):
    queryset = GroupTagMapping.objects.all()
    serializer_class = GroupTagMappingSerializer
    filterset_fields = ('connection_id', 'group_email')


class GroupTagMappingDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = GroupTagMapping.objects.all()
    serializer_class = GroupTagMappingSerializer
