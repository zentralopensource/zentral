from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import (ArtifactDetail, ArtifactList,
                        BlueprintDetail, BlueprintList,
                        BlueprintArtifactDetail, BlueprintArtifactList,
                        FileVaultConfigDetail, FileVaultConfigList,
                        ProfileDetail, ProfileList,
                        RecoveryPasswordConfigList, RecoveryPasswordConfigDetail,
                        DEPVirtualServerSyncDevicesView,
                        EnrolledDeviceFileVaultPRK, EnrolledDeviceRecoveryPassword,
                        SyncSoftwareUpdatesView)


app_name = "mdm_api"
urlpatterns = [
    path('artifacts/', ArtifactList.as_view(), name="artifacts"),
    path('artifacts/<uuid:pk>/', ArtifactDetail.as_view(), name="artifact"),
    path('blueprints/', BlueprintList.as_view(), name="blueprints"),
    path('blueprints/<int:pk>/', BlueprintDetail.as_view(), name="blueprint"),
    path('blueprint_artifacts/', BlueprintArtifactList.as_view(), name="blueprint_artifacts"),
    path('blueprint_artifacts/<int:pk>/', BlueprintArtifactDetail.as_view(), name="blueprint_artifact"),
    path('filevault_configs/', FileVaultConfigList.as_view(), name="filevault_configs"),
    path('filevault_configs/<int:pk>/', FileVaultConfigDetail.as_view(), name="filevault_config"),
    path('profiles/', ProfileList.as_view(), name="profiles"),
    path('profiles/<uuid:artifact_version_pk>/', ProfileDetail.as_view(), name="profile"),
    path('recovery_password_configs/', RecoveryPasswordConfigList.as_view(), name="recovery_password_configs"),
    path('recovery_password_configs/<int:pk>/', RecoveryPasswordConfigDetail.as_view(),
         name="recovery_password_config"),

    path('dep/virtual_servers/<int:pk>/sync_devices/',
         DEPVirtualServerSyncDevicesView.as_view(), name="dep_virtual_server_sync_devices"),
    path('enrolled_devices/<int:pk>/filevault_prk/', EnrolledDeviceFileVaultPRK.as_view(),
         name="enrolled_device_filevault_prk"),
    path('enrolled_devices/<int:pk>/recovery_password/', EnrolledDeviceRecoveryPassword.as_view(),
         name="enrolled_device_recovery_password"),
    path('software_updates/sync/',
         SyncSoftwareUpdatesView.as_view(), name="sync_software_updates"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
