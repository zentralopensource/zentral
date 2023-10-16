from django.urls import path
from . import views

app_name = "mdm"
urlpatterns = [
    # setup views

    path('',
         views.IndexView.as_view(),
         name='index'),
    path('root_ca/',
         views.RootCAView.as_view(),
         name='root_ca'),

    # push certificate / setup views
    path('push_certificates/',
         views.PushCertificatesView.as_view(),
         name='push_certificates'),
    path('push_certificates/add/',
         views.AddPushCertificateView.as_view(),
         name='add_push_certificate'),
    path('push_certificates/<int:pk>/',
         views.PushCertificateView.as_view(),
         name='push_certificate'),
    path('push_certificates/<int:pk>/update/',
         views.UpdatePushCertificateView.as_view(),
         name="update_push_certificate"),
    path('push_certificates/<int:pk>/delete/',
         views.DeletePushCertificateView.as_view(),
         name="delete_push_certificate"),

    # DEP tokens / setup views
    path('dep/tokens/<int:pk>/download_public_key/',
         views.DownloadDEPTokenPublicKeyView.as_view(),
         name='download_dep_token_public_key'),
    path('dep/tokens/<int:pk>/renew/',
         views.RenewDEPTokenView.as_view(),
         name='renew_dep_token'),

    # DEP virtual servers / setup views
    path('dep/virtual-servers/',
         views.DEPVirtualServersView.as_view(),
         name="dep_virtual_servers"),
    path('dep/virtual-servers/connect/',
         views.ConnectDEPVirtualServerView.as_view(),
         name="connect_dep_virtual_server"),
    path('dep/virtual-servers/<int:pk>/',
         views.DEPVirtualServerView.as_view(),
         name="dep_virtual_server"),
    path('dep/virtual-servers/<int:pk>/update/',
         views.UpdateDEPVirtualServerView.as_view(),
         name="update_dep_virtual_server"),

    # Locations
    path('locations/', views.LocationsView.as_view(),
         name='locations'),
    path('locations/create/', views.CreateLocationView.as_view(),
         name='create_location'),
    path('locations/<int:pk>/', views.LocationView.as_view(),
         name='location'),
    path('locations/<int:pk>/update/', views.UpdateLocationView.as_view(),
         name='update_location'),
    path('locations/<int:pk>/delete/', views.DeleteLocationView.as_view(),
         name='delete_location'),

    # management views
    path('enrollments/', views.EnrollmentListView.as_view(), name="enrollments"),

    # DEP enrollments
    path('enrollments/dep/create/',
         views.CreateDEPEnrollmentView.as_view(),
         name="create_dep_enrollment"),
    path('enrollments/dep/<int:pk>/',
         views.DEPEnrollmentView.as_view(),
         name='dep_enrollment'),
    path('enrollments/dep/<int:pk>/check/',
         views.CheckDEPEnrollmentView.as_view(),
         name='check_dep_enrollment'),
    path('enrollments/dep/<int:pk>/update/',
         views.UpdateDEPEnrollmentView.as_view(),
         name='update_dep_enrollment'),

    # OTA enrollments
    path('enrollments/ota/create/',
         views.CreateOTAEnrollmentView.as_view(),
         name='create_ota_enrollment'),
    path('enrollments/ota/<int:pk>/',
         views.OTAEnrollmentView.as_view(),
         name='ota_enrollment'),
    path('enrollments/ota/<int:pk>/download/',
         views.DownloadProfileServicePayloadView.as_view(),
         name='download_profile_service_payload'),
    path('enrollments/ota/<int:pk>/revoke/',
         views.RevokeOTAEnrollmentView.as_view(),
         name='revoke_ota_enrollment'),
    path('enrollments/ota/<int:pk>/update/',
         views.UpdateOTAEnrollmentView.as_view(),
         name='update_ota_enrollment'),

    # user enrollments
    path('enrollments/user/create/',
         views.CreateUserEnrollmentView.as_view(),
         name='create_user_enrollment'),
    path('enrollments/user/<int:pk>/',
         views.UserEnrollmentView.as_view(),
         name='user_enrollment'),
    path('enrollments/user/<int:pk>/revoke/',
         views.RevokeUserEnrollmentView.as_view(),
         name='revoke_user_enrollment'),
    path('enrollments/user/<int:pk>/update/',
         views.UpdateUserEnrollmentView.as_view(),
         name='update_user_enrollment'),

    # artifacts
    path('artifacts/',
         views.ArtifactListView.as_view(),
         name="artifacts"),
    path('artifacts/upload/profile/',
         views.UploadProfileView.as_view(),
         name="upload_profile"),
    path('artifacts/upload/enterprise_app/',
         views.UploadEnterpriseAppView.as_view(),
         name="upload_enterprise_app"),
    path('artifacts/<uuid:pk>/',
         views.ArtifactView.as_view(),
         name="artifact"),
    path('artifacts/<uuid:pk>/update/',
         views.UpdateArtifactView.as_view(),
         name="update_artifact"),
    path('artifacts/<uuid:pk>/delete/',
         views.DeleteArtifactView.as_view(),
         name="delete_artifact"),
    # blueprint artifacts
    path('artifacts/<uuid:pk>/blueprint_artifact/create/',
         views.CreateBlueprintArtifactView.as_view(),
         name="create_blueprint_artifact"),
    path('artifacts/<uuid:artifact_pk>/blueprint_artifact/<int:pk>/update/',
         views.UpdateBlueprintArtifactView.as_view(),
         name="update_blueprint_artifact"),
    path('artifacts/<uuid:artifact_pk>/blueprint_artifact/<int:pk>/delete/',
         views.DeleteBlueprintArtifactView.as_view(),
         name="delete_blueprint_artifact"),
    # artifact versions
    path('artifacts/<uuid:artifact_pk>/versions/<uuid:pk>/',
         views.ArtifactVersionView.as_view(),
         name="artifact_version"),
    path('artifacts/<uuid:artifact_pk>/versions/<uuid:pk>/update/',
         views.UpdateArtifactVersionView.as_view(),
         name="update_artifact_version"),
    path('artifacts/<uuid:pk>/upgrade_enterprise_app/',
         views.UpgradeEnterpriseAppView.as_view(),
         name="upgrade_enterprise_app"),
    path('artifacts/<uuid:pk>/upgrade_profile/',
         views.UpgradeProfileView.as_view(),
         name="upgrade_profile"),
    path('artifacts/<uuid:pk>/upgrade_store_app/',
         views.UpgradeStoreAppView.as_view(),
         name="upgrade_store_app"),
    path('artifacts/<uuid:artifact_pk>/versions/<uuid:pk>/delete/',
         views.DeleteArtifactVersionView.as_view(),
         name="delete_artifact_version"),
    path('profiles/<uuid:artifact_version_pk>/download/',
         views.DownloadProfileView.as_view(),
         name="download_profile"),

    # assets
    path('assets/',
         views.AssetListView.as_view(),
         name="assets"),
    path('assets/<int:pk>/',
         views.AssetView.as_view(),
         name="asset"),
    path('assets/<int:pk>/create_artifact/',
         views.CreateAssetArtifactView.as_view(),
         name="create_asset_artifact"),

    # blueprints
    path('blueprints/',
         views.BlueprintListView.as_view(),
         name="blueprints"),
    path('blueprints/create/',
         views.CreateBlueprintView.as_view(),
         name="create_blueprint"),
    path('blueprints/<int:pk>/',
         views.BlueprintView.as_view(),
         name="blueprint"),
    path('blueprints/<int:pk>/update/',
         views.UpdateBlueprintView.as_view(),
         name="update_blueprint"),
    path('blueprints/<int:pk>/delete/',
         views.DeleteBlueprintView.as_view(),
         name="delete_blueprint"),

    # FileVault configurations
    path('filevault_configurations/',
         views.FileVaultConfigListView.as_view(),
         name="filevault_configs"),
    path('filevault_configurations/create/',
         views.CreateFileVaultConfigView.as_view(),
         name="create_filevault_config"),
    path('filevault_configurations/<int:pk>/',
         views.FileVaultConfigView.as_view(),
         name="filevault_config"),
    path('filevault_configurations/<int:pk>/update/',
         views.UpdateFileVaultConfigView.as_view(),
         name="update_filevault_config"),
    path('filevault_configurations/<int:pk>/delete/',
         views.DeleteFileVaultConfigView.as_view(),
         name="delete_filevault_config"),

    # Recovery password configurations
    path('recovery_password_configurations/',
         views.RecoveryPasswordConfigListView.as_view(),
         name="recovery_password_configs"),
    path('recovery_password_configurations/create/',
         views.CreateRecoveryPasswordConfigView.as_view(),
         name="create_recovery_password_config"),
    path('recovery_password_configurations/<int:pk>/',
         views.RecoveryPasswordConfigView.as_view(),
         name="recovery_password_config"),
    path('recovery_password_configurations/<int:pk>/update/',
         views.UpdateRecoveryPasswordConfigView.as_view(),
         name="update_recovery_password_config"),
    path('recovery_password_configurations/<int:pk>/delete/',
         views.DeleteRecoveryPasswordConfigView.as_view(),
         name="delete_recovery_password_config"),

    # SCEP configurations
    path('scep_configurations/',
         views.SCEPConfigListView.as_view(),
         name="scep_configs"),
    path('scep_configurations/create/',
         views.CreateSCEPConfigView.as_view(),
         name="create_scep_config"),
    path('scep_configurations/<int:pk>/',
         views.SCEPConfigView.as_view(),
         name="scep_config"),
    path('scep_configurations/<int:pk>/update/',
         views.UpdateSCEPConfigView.as_view(),
         name="update_scep_config"),
    path('scep_configurations/<int:pk>/delete/',
         views.DeleteSCEPConfigView.as_view(),
         name="delete_scep_config"),

    # enrolled devices
    path('devices/',
         views.EnrolledDeviceListView.as_view(),
         name="enrolled_devices"),
    path('devices/<int:pk>/',
         views.EnrolledDeviceView.as_view(),
         name="enrolled_device"),
    path('devices/<int:pk>/commands/',
         views.EnrolledDeviceCommandsView.as_view(),
         name="enrolled_device_commands"),
    path('devices/<int:pk>/poke/',
         views.PokeEnrolledDeviceView.as_view(),
         name="poke_enrolled_device"),
    path('devices/<int:pk>/change_blueprint/',
         views.ChangeEnrolledDeviceBlueprintView.as_view(),
         name="change_enrolled_device_blueprint"),
    path('devices/<int:pk>/block/',
         views.BlockEnrolledDeviceView.as_view(),
         name="block_enrolled_device"),
    path('devices/<int:pk>/clear_release/',
         views.UnblockEnrolledDeviceView.as_view(),
         name="unblock_enrolled_device"),

    # enrolled device commands
    path('devices/<int:pk>/commands/<str:db_name>/create/',
         views.CreateEnrolledDeviceCommandView.as_view(),
         name="create_enrolled_device_command"),
    path('devices/commands/<uuid:uuid>/result/',
         views.DownloadEnrolledDeviceCommandResultView.as_view(),
         name="download_enrolled_device_command_result"),

    # enrolled device users
    path('devices/<int:device_pk>/users/<int:pk>/',
         views.EnrolledUserView.as_view(),
         name="enrolled_user"),
    path('devices/<int:device_pk>/users/<int:pk>/commands/',
         views.EnrolledUserCommandsView.as_view(),
         name="enrolled_user_commands"),
    path('devices/<int:device_pk>/users/<int:pk>/poke/',
         views.PokeEnrolledUserView.as_view(),
         name="poke_enrolled_user"),

    # enrolled user commands
    path('users/commands/<uuid:uuid>/result/',
         views.DownloadEnrolledUserCommandResultView.as_view(),
         name="download_enrolled_user_command_result"),

    # DEP devices
    path('dep/devices/',
         views.DEPDeviceListView.as_view(),
         name="dep_devices"),
    path('dep/devices/<int:pk>/',
         views.DEPDeviceDetailView.as_view(),
         name="dep_device"),
    path('dep/devices/<int:pk>/assign_profile/',
         views.AssignDEPDeviceProfileView.as_view(),
         name="assign_dep_device_profile"),
    path('dep/devices/<int:pk>/refresh/',
         views.RefreshDEPDeviceView.as_view(),
         name="refresh_dep_device"),

    # terraform
    path('terraform_export/',
         views.TerraformExportView.as_view(),
         name="terraform_export"),
]

modules_menu_cfg = {
    'title': 'MDM',
    'items': (
        ('index', 'Overview', False, ('mdm',)),
        ('enrollments', 'Enrollments', False, ('mdm',)),
        ('enrolled_devices', 'Devices', False, ('mdm.view_enrolleddevice',)),
        ('artifacts', 'Artifacts', False, ('mdm.view_artifact',)),
        ('blueprints', 'Blueprints', False, ('mdm.view_blueprint',)),
    ),
    'weight': 10,
}
