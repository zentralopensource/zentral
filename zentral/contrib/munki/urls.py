from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^probes/$', views.ProbesView.as_view(), name='probes'),
    url(r'^probes/(?P<probe_key>[\S ]+)/$', views.ProbeView.as_view(), name='probe'),
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    # API
    url(r'^job_details/$', csrf_exempt(views.JobDetailsView.as_view())),
    url(r'^post_job/$', csrf_exempt(views.PostJobView.as_view()))
]


main_menu_cfg = {
    'items': (
        ('probes', 'Probes'),
        ('enrollment', 'Enrollment'),
    )
}
