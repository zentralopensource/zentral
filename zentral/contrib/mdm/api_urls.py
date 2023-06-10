from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (ArtifactDetail, ArtifactList,
                        BlueprintDetail, BlueprintList,
                        ProfileDetail, ProfileList,
                        DEPVirtualServerSyncDevicesView)


app_name = "mdm_api"
urlpatterns = [
    path('artifacts/', ArtifactList.as_view(), name="artifacts"),
    path('artifacts/<uuid:pk>/', ArtifactDetail.as_view(), name="artifact"),
    path('blueprints/', BlueprintList.as_view(), name="blueprints"),
    path('blueprints/<int:pk>/', BlueprintDetail.as_view(), name="blueprint"),
    path('profiles/', ProfileList.as_view(), name="profiles"),
    path('profiles/<uuid:artifact_version_pk>/', ProfileDetail.as_view(), name="profile"),

    path('dep/virtual_servers/<int:pk>/sync_devices/',
         DEPVirtualServerSyncDevicesView.as_view(), name="dep_virtual_server_sync_devices")
]


urlpatterns = format_suffix_patterns(urlpatterns)
