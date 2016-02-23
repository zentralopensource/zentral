from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    url(r'^probes/$', views.ProbesView.as_view(), name='probes'),
    url(r'^probes/(?P<probe_key>[\S ]+)/$', views.ProbeView.as_view(), name='probe'),
    # API
    url(r'^preflight/(?P<machine_id>\S+)$', csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    url(r'^ruledownload/(?P<machine_id>\S+)$', csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    url(r'^eventupload/(?P<machine_id>\S+)$', csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    url(r'^logupload/(?P<machine_id>\S+)$', csrf_exempt(views.LogUploadView.as_view()), name='logupload'),
    url(r'^postflight/(?P<machine_id>\S+)$', csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]


main_menu_cfg = {
    'items': (
        ('probes', 'Probes'),
        ('enrollment', 'Enrollment'),
    )
}
