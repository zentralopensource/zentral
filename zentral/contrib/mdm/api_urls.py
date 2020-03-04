from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import DEPVirtualServerSyncDevicesView


app_name = "mdm_api"
urlpatterns = [
    path('dep/virtual_servers/<int:pk>/sync_devices/',
         DEPVirtualServerSyncDevicesView.as_view(), name="dep_virtual_server_sync_devices")
]


urlpatterns = format_suffix_patterns(urlpatterns)
