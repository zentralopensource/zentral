from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from zentral.core.events.base import EventRequest
from zentral.utils.drf import (DefaultDjangoModelPermissions, DjangoPermissionRequired,
                               ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit)
from .models import Tenant
from .serializers import TenantSerializer
from .tasks import sync_inventory


class TenantList(ListCreateAPIViewWithAudit):
    """
    List or Create Tenants
    """
    queryset = Tenant.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = TenantSerializer


class TenantDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Tenant instance.
    """
    lookup_field = "tenant_id"
    queryset = Tenant.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = TenantSerializer


class StartTenantSync(APIView):
    """
    Start tenant inventory synchronization
    """
    permission_required = ("intune.view_tenant", "inventory.change_machinesnapshot")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        tenant = get_object_or_404(Tenant, tenant_id=self.kwargs["tenant_id"])
        result = sync_inventory.apply_async(kwargs={'tenant_id': tenant.tenant_id})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)
