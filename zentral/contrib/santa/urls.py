from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # django admin
    url(r'^enrollment/$', views.EnrollmentView.as_view(), name='enrollment'),
    url(r'^enrollment/debugging/$', views.EnrollmentDebuggingView.as_view(), name='enrollment_debugging'),
    url(r'^installer_package/$', views.InstallerPackageView.as_view(), name='installer_package'),
    url(r'^probes/create/$', views.CreateProbeView.as_view(), name='create_probe'),
    url(r'^probes/(?P<probe_id>\d+)/rules/add/$',
        views.AddProbeRuleView.as_view(), name='add_probe_rule'),
    url(r'^probes/(?P<probe_id>\d+)/rules/(?P<rule_id>\d+)/update/$',
        views.UpdateProbeRuleView.as_view(), name='update_probe_rule'),
    url(r'^probes/(?P<probe_id>\d+)/rules/(?P<rule_id>\d+)/delete/$',
        views.DeleteProbeRuleView.as_view(), name='delete_probe_rule'),
    # API
    url(r'^preflight/(?P<machine_id>\S+)$', csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    url(r'^ruledownload/(?P<machine_id>\S+)$', csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    url(r'^eventupload/(?P<machine_id>\S+)$', csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    url(r'^logupload/(?P<machine_id>\S+)$', csrf_exempt(views.LogUploadView.as_view()), name='logupload'),
    url(r'^postflight/(?P<machine_id>\S+)$', csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]


setup_menu_cfg = {
    'items': (
        ('enrollment', 'Enrollment'),
    )
}
