import logging
from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.drf import DjangoPermissionRequired
from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.tasks import sync_group_tag_mappings_task


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
