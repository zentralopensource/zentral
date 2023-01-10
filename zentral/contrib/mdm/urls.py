from django.urls import path
from django.views.decorators.csrf import csrf_exempt
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
    path('locations/<uuid:mdm_info_id>/notify/', csrf_exempt(views.NotifyLocationView.as_view()),
         name='notify_location'),

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
    path('enrollments/ota/<int:pk>/enroll/',
         views.OTAEnrollmentEnrollView.as_view(),
         name='ota_enrollment_enroll'),

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
    path('enrollment/user/<int:pk>/enroll/',
         views.UserEnrollmentEnrollView.as_view(),
         name='user_enrollment_enroll'),

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
    path('artifacts/<uuid:pk>/trash/',
         views.TrashArtifactView.as_view(),
         name="trash_artifact"),
    path('artifacts/<uuid:pk>/blueprint_artifact/create/',
         views.CreateBlueprintArtifactView.as_view(),
         name="create_blueprint_artifact"),
    path('artifacts/<uuid:artifact_pk>/blueprint_artifact/<int:pk>/update/',
         views.UpdateBlueprintArtifactView.as_view(),
         name="update_blueprint_artifact"),
    path('artifacts/<uuid:artifact_pk>/blueprint_artifact/<int:pk>/delete/',
         views.DeleteBlueprintArtifactView.as_view(),
         name="delete_blueprint_artifact"),

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

    # enrolled device commands
    path('devices/<int:pk>/commands/custom/create/',
         views.CreateEnrolledDeviceCustomCommandView.as_view(),
         name="create_enrolled_device_custom_command"),
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
    path('dep/devices/<int:pk>/assign_profile/',
         views.AssignDEPDeviceProfileView.as_view(),
         name="assign_dep_device_profile"),
    path('dep/devices/<int:pk>/refresh/',
         views.RefreshDEPDeviceView.as_view(),
         name="refresh_dep_device"),

    # SCEP verification / scep view
    path('verify_scep_csr/',
         csrf_exempt(views.VerifySCEPCSRView.as_view()),
         name='verify_scep_csr'),

    # OTA protocol / ota view
    path('ota_enroll/', csrf_exempt(views.OTAEnrollView.as_view()),
         kwargs={"session": False}, name='ota_enroll'),
    path('ota_session_enroll/', csrf_exempt(views.OTAEnrollView.as_view()),
         kwargs={"session": True}, name='ota_session_enroll'),

    # DEP protocol / dep views
    path('dep_enroll/<str:dep_enrollment_secret>/',
         csrf_exempt(views.DEPEnrollView.as_view()), name='dep_enroll'),
    path('dep_web_enroll/<str:dep_enrollment_secret>/',
         views.DEPWebEnrollView.as_view(), name='dep_web_enroll'),
    path('dep_enrollment_session/<str:dep_enrollment_session_secret>/',
         views.DEPEnrollmentSessionView.as_view(), name='dep_enrollment_session'),

    # User Enrollment protocol / user views
    path('user_enrollment/<str:secret>/com.apple.remotemanagement/',
         csrf_exempt(views.UserEnrollmentServiceDiscoveryView.as_view()), name='user_enrollment_service_discovery'),
    path('user_enrollment/<str:secret>/enroll/',
         csrf_exempt(views.EnrollUserView.as_view()), name='enroll_user'),
    path('user_enrollment_session/<str:secret>/authenticate/',
         csrf_exempt(views.AuthenticateUserView.as_view()), name='authenticate_user'),

    # MDM protocol / mdm views
    path('checkin/', csrf_exempt(views.CheckinView.as_view()), name='checkin'),
    path('connect/', csrf_exempt(views.ConnectView.as_view()), name='connect'),
    path('device_commands/<uuid:uuid>/enterprise_app/',
         views.EnterpriseAppDownloadView.as_view(),
         name="enterprise_app_download"),
    path('profiles/<uuid:pk>/',
         views.ProfileDownloadView.as_view(),
         name="profile_download_view"),
]

setup_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('mdm',)),
        ('enrollments', 'Enrollments', False, ('mdm',)),
        ('enrolled_devices', 'Devices', False, ('mdm.view_enrolleddevice',)),
        ('artifacts', 'Artifacts', False, ('mdm.view_artifact',)),
        ('blueprints', 'Blueprints', False, ('mdm.view_blueprint',)),
    )
}
