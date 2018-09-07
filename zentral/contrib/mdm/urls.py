from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # setup views
    url(r'^$',
        views.IndexView.as_view(),
        name='index'),
    url(r'^root_ca/$',
        views.RootCAView.as_view(),
        name='root_ca'),

    url(r'^business_units/$',
        views.MetaBusinessUnitListView.as_view(),
        name='mbu_list'),
    url(r'^business_units/(?P<pk>\d+)/$',
        views.MetaBusinessUnitDetailView.as_view(),
        name='mbu'),

    # push certificate / setup views
    url(r'^push_certificates/$',
        views.PushCertificatesView.as_view(),
        name='push_certificates'),
    url(r'^push_certificates/add/$',
        views.AddPushCertificateView.as_view(),
        name='add_push_certificate'),
    url(r'^push_certificates/(?P<pk>\d+)/$',
        views.PushCertificateView.as_view(),
        name='push_certificate'),
    url(r'^push_certificates/(?P<pk>\d+)/add_business_unit/$',
        views.AddPushCertificateBusinessUnitView.as_view(),
        name='add_push_certificate_business_unit'),
    url(r'^push_certificates/(?P<pk>\d+)/remove_business_unit/$',
        views.RemovePushCertificateBusinessUnitView.as_view(),
        name='remove_push_certificate_business_unit'),

    # OTA enrollment / setup views
    url(r'^enrollment/ota/$',
        views.OTAEnrollmentListView.as_view(),
        name='ota_enrollments'),
    url(r'^enrollment/ota/create/$',
        views.CreateOTAEnrollmentView.as_view(),
        name='create_ota_enrollment'),
    url(r'^enrollment/ota/(?P<pk>\d+)/$',
        views.OTAEnrollmentView.as_view(),
        name='ota_enrollment'),
    url(r'^enrollment/ota/(?P<pk>\d+)/download/$',
        views.DownloadProfileServicePayloadView.as_view(),
        name='download_profile_service_payload'),
    url(r'^enrollment/ota/(?P<pk>\d+)/revoke/$',
        views.RevokeOTAEnrollmentView.as_view(),
        name='revoke_ota_enrollment'),

    # DEP tokens / setup views
    url(r'^dep/tokens/(?P<pk>\d+)/download_public_key/$',
        views.DownloadDEPTokenPublicKeyView.as_view(),
        name='download_dep_token_public_key'),

    # DEP virtual servers / setup views
    url(r'^dep/virtual-servers/$',
        views.DEPVirtualServersView.as_view(),
        name="dep_virtual_servers"),
    url(r'^dep/virtual-servers/connect/$',
        views.ConnectDEPVirtualServerView.as_view(),
        name="connect_dep_virtual_server"),
    url(r'^dep/virtual-servers/(?P<pk>\d+)/$',
        views.DEPVirtualServerView.as_view(),
        name="dep_virtual_server"),
    url(r'^dep/virtual-servers/(?P<pk>\d+)/profiles/create/$',
        views.CreateDEPProfileView.as_view(),
        name="create_dep_profile"),

    # DEP devices / setup views
    url(r'^dep/devices/(?P<pk>\d+)/assign_profile/$',
        views.AssignDEPDeviceProfileView.as_view(),
        name="assign_dep_device_profile"),
    url(r'^dep/devices/(?P<pk>\d+)/refresh/$',
        views.RefreshDEPDeviceView.as_view(),
        name="refresh_dep_device"),

    # DEP profiles / setup views
    url(r'^dep/profiles/$',
        views.DEPProfilesView.as_view(),
        name='dep_profiles'),
    url(r'^dep/profiles/(?P<pk>\d+)/$',
        views.DEPProfileView.as_view(),
        name='dep_profile'),
    url(r'^dep/profiles/(?P<pk>\d+)/check/$',
        views.CheckDEPProfileView.as_view(),
        name='check_dep_profile'),
    url(r'^dep/profiles/(?P<pk>\d+)/update/$',
        views.UpdateDEPProfileView.as_view(),
        name='update_dep_profile'),

    # enrolled devices / management views
    url(r'^devices/$',
        views.DevicesView.as_view(),
        name="devices"),
    url(r'^devices/(?P<serial_number>\S+)/$',
        views.DeviceView.as_view(),
        name="device"),
    url(r'^enrolled_devices/(?P<pk>\d+)/poke/$',
        views.PokeEnrolledDeviceView.as_view(),
        name="poke_enrolled_device"),

    # kernel extensions / management views
    url(r'^kernel_extensions/$',
        views.KernelExtensionsIndexView.as_view(),
        name="kernel_extensions_index"),
    url(r'^kernel_extensions/create_team/$',
        views.CreateKernelExtensionTeamView.as_view(),
        name="create_kernel_extension_team"),
    url(r'^kernel_extensions/create/$',
        views.CreateKernelExtensionView.as_view(),
        name="create_kernel_extension"),
    url(r'^kernel_extensions/policies/create/$',
        views.CreateKernelExtensionPolicyView.as_view(),
        name="create_kernel_extension_policy"),
    url(r'^kernel_extensions/policies/(?P<pk>\d+)/$',
        views.KernelExtensionPolicyView.as_view(),
        name="kernel_extension_policy"),
    url(r'^kernel_extensions/policies/(?P<pk>\d+)/update/$',
        views.UpdateKernelExtensionPolicyView.as_view(),
        name="update_kernel_extension_policy"),

    # enrollment packages / management
    url(r'^enrollment_packages/$',
        views.EnrollmentPackagesIndexView.as_view(),
        name="enrollment_packages_index"),
    url(r'^enrollment_packages/create/$',
        views.CreateEnrollmentPackageView.as_view(),
        name="create_enrollment_package"),


    # SCEP verification / scep view
    url(r'^verify_scep_csr/$',
        csrf_exempt(views.VerifySCEPCSRView.as_view()),
        name='verify_scep_csr'),

    # OTA protocol / ota view
    url(r'^ota_enroll/$', csrf_exempt(views.OTAEnrollView.as_view()), name='ota_enroll'),

    # DEP protocol / dep view
    url(r'^dep_enroll/(?P<dep_profile_secret>\S+)/$', csrf_exempt(views.DEPEnrollView.as_view()), name='dep_enroll'),

    # MDM protocol / mdm views
    url(r'^checkin/$', csrf_exempt(views.CheckinView.as_view()), name='checkin'),
    url(r'^connect/$', csrf_exempt(views.ConnectView.as_view()), name='connect'),
    # MDM protocol / InstallApplication command
    url(r'^device_artifact_commands/(?P<uuid>[0-9a-f-]+)/manifest/$',
        views.InstallApplicationManifestView.as_view(),
        name="install_application_manifest"),
    url(r'^device_artifact_commands/(?P<uuid>[0-9a-f-]+)/download/$',
        views.InstallApplicationDownloadView.as_view(),
        name="install_application_download"),
]

setup_menu_cfg = {
    'items': (
        ('index', 'Setup'),
    )
}
