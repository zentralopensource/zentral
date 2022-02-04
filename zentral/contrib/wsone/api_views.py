from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.core.events.base import EventRequest
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .models import Instance
from .serializers import InstanceSerializer
from .tasks import sync_inventory


class InstanceList(generics.ListAPIView):
    """
    List all Instances
    """
    queryset = Instance.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = InstanceSerializer


class InstanceDetail(generics.RetrieveAPIView):
    """
    Retrieve an Instance
    """
    queryset = Instance.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = InstanceSerializer


class StartInstanceSync(APIView):
    """
    Start instance inventory synchronization
    """
    permission_required = ("wsone.view_instance", "inventory.change_machinesnapshot")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        instance = get_object_or_404(Instance, pk=self.kwargs["pk"])
        event_request = EventRequest.build_from_request(request)
        result = sync_inventory.apply_async((instance.pk, event_request.serialize()))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)
