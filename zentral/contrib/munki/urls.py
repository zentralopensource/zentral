from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    # install probe
    url(r'^install_probes/create/$',
        views.CreateInstallProbeView.as_view(), name='create_install_probe'),
    url(r'^install_probes/(?P<probe_id>\d+)/update/$',
        views.UpdateInstallProbeView.as_view(), name='update_install_probe'),
    # API
    url(r'^job_details/$', csrf_exempt(views.JobDetailsView.as_view())),
    url(r'^post_job/$', csrf_exempt(views.PostJobView.as_view()))
]


setup_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
