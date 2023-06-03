from django.urls import path

from .api_views import StartTenantSync, TenantDetail, TenantList

app_name = "intune_api"
urlpatterns = [
    path('tenants/', TenantList.as_view(), name="tenants"),
    path('tenants/<uuid:tenant_id>/', TenantDetail.as_view(), name="tenant"),
    path('tenants/<uuid:tenant_id>/sync/', StartTenantSync.as_view(), name="start_tenant_sync"),
]
