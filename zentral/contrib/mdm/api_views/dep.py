from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.contrib.mdm.models import DEPVirtualServer
from zentral.contrib.mdm.tasks import sync_dep_virtual_server_devices_task


class DEPVirtualServerSyncDevicesView(APIView):
    def post(self, request, *args, **kwargs):
        server = get_object_or_404(DEPVirtualServer, pk=kwargs["pk"])
        result = sync_dep_virtual_server_devices_task.apply_async((server.pk,))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)
