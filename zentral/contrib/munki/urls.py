from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "munki"
urlpatterns = [
    # enrollment
    url(r'^enrollments/$',
        views.EnrollmentListView.as_view(),
        name='enrollment_list'),
    url(r'^enrollments/create/$',
        views.CreateEnrollmentView.as_view(),
        name='create_enrollment'),
    url(r'^enrollments/(?P<pk>\d+)/package/$',
        views.EnrollmentPackageView.as_view(),
        name='enrollment_package'),

    # enrollment endpoint called by enrollment script
    url(r'^enroll/$', csrf_exempt(views.EnrollView.as_view()),
        name='enroll'),

    # install probe
    url(r'^install_probes/create/$',
        views.CreateInstallProbeView.as_view(), name='create_install_probe'),
    url(r'^install_probes/(?P<probe_id>\d+)/update/$',
        views.UpdateInstallProbeView.as_view(), name='update_install_probe'),

    # API
    url(r'^job_details/$', csrf_exempt(views.JobDetailsView.as_view()), name="job_details"),
    url(r'^post_job/$', csrf_exempt(views.PostJobView.as_view()), name="post_job")
]


setup_menu_cfg = {
    'items': (
        ('enrollment_list', 'Enrollments'),
    )
}
