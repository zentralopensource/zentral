from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # setup
    url(r'^root_ca/$',
        views.RootCAView.as_view(),
        name='root_ca'),
    url(r'^enrollment/$',
        views.EnrollmentView.as_view(),
        name='enrollment'),
    url(r'^enrollment/push_certificates/$',
        views.PushCertificatesView.as_view(),
        name='push_certificates'),
    url(r'^enrollment/push_certificates/add/$',
        views.AddPushCertificateView.as_view(),
        name='add_push_certificate'),
    url(r'^enrollment/push_certificates/(?P<pk>\d+)/$',
        views.PushCertificateView.as_view(),
        name='push_certificate'),
    url(r'^enrollment/push_certificates/(?P<pk>\d+)/add_business_unit/$',
        views.AddPushCertificateBusinessUnitView.as_view(),
        name='add_push_certificate_business_unit'),
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

    # enrolled devices
    url(r'^enrolled_devices/$',
        views.EnrolledDevicesView.as_view(),
        name="enrolled_devices"),
    url(r'^enrolled_devices/(?P<pk>\d+)/$',
        views.EnrolledDeviceView.as_view(),
        name="enrolled_device"),
    url(r'^enrolled_devices/(?P<pk>\d+)/poke/$',
        views.PokeEnrolledDeviceView.as_view(),
        name="poke_enrolled_device"),

    # scep verification
    url(r'^verify_scep_csr/$',
        csrf_exempt(views.VerifySCEPCSRView.as_view()),
        name='verify_scep_csr'),

    # ota protocol
    url(r'^ota_enroll/$', csrf_exempt(views.OTAEnrollView.as_view()), name='ota_enroll'),

    # mdm protocol
    url(r'^checkin/$', csrf_exempt(views.CheckinView.as_view()), name='checkin'),
    url(r'^connect/$', csrf_exempt(views.ConnectView.as_view()), name='connect'),
]


setup_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
