from django.urls import reverse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.contrib.mdm.tasks import sync_software_updates_task
from zentral.utils.drf import DjangoPermissionRequired


class SyncSoftwareUpdatesView(APIView):
    permission_required = (
        "mdm.add_softwareupdate",
        "mdm.change_softwareupdate",
        "mdm.delete_softwareupdate",
    )
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        result = sync_software_updates_task.apply_async()
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)
