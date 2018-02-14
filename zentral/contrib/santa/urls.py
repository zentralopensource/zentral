from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # enrollment
    url(r'^configurations/$',
        views.ConfigurationListView.as_view(),
        name='configuration_list'),
    url(r'^configurations/create/$',
        views.CreateConfigurationView.as_view(),
        name='create_configuration'),
    url(r'^configurations/(?P<pk>\d+)/$',
        views.ConfigurationView.as_view(),
        name='configuration'),
    url(r'^configurations/(?P<pk>\d+)/update/$',
        views.UpdateConfigurationView.as_view(),
        name='update_configuration'),
    url(r'^configurations/(?P<pk>\d+)/enrollments/create/$',
        views.CreateEnrollmentView.as_view(),
        name='create_enrollment'),
    url(r'^configurations/(?P<configuration_pk>\d+)/enrollments/(?P<pk>\d+)/$',
        views.EnrollmentPackageView.as_view(),
        name='enrollment_package'),
    # enrollment endpoint called by enrollment script
    url(r'^enroll/$', csrf_exempt(views.EnrollView.as_view()),
        name='enroll'),

    # probes
    url(r'^probes/create/$', views.CreateProbeView.as_view(), name='create_probe'),
    url(r'^probes/(?P<probe_id>\d+)/rules/add/$',
        views.AddProbeRuleView.as_view(), name='add_probe_rule'),
    url(r'^probes/(?P<probe_id>\d+)/rules/(?P<rule_id>\d+)/update/$',
        views.UpdateProbeRuleView.as_view(), name='update_probe_rule'),
    url(r'^probes/(?P<probe_id>\d+)/rules/(?P<rule_id>\d+)/delete/$',
        views.DeleteProbeRuleView.as_view(), name='delete_probe_rule'),
    url(r'probes/(?P<probe_id>\d+)/rules/pick_application/$',
        views.PickRuleApplicationView.as_view(), name='pick_rule_app'),
    url(r'probes/(?P<probe_id>\d+)/rules/pick_certificate/$',
        views.PickRuleCertificateView.as_view(), name='pick_rule_cert'),

    # API
    url(r'^preflight/(?P<machine_id>\S+)$', csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    url(r'^ruledownload/(?P<machine_id>\S+)$', csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    url(r'^eventupload/(?P<machine_id>\S+)$', csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    url(r'^logupload/(?P<machine_id>\S+)$', csrf_exempt(views.LogUploadView.as_view()), name='logupload'),
    url(r'^postflight/(?P<machine_id>\S+)$', csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]


setup_menu_cfg = {
    'items': (
        ('configuration_list', 'Configurations'),
    )
}
