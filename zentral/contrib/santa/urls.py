from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "santa"
urlpatterns = [
    # configuration / enrollment
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
    url(r'^configurations/(?P<configuration_pk>\d+)/enrollments/(?P<pk>\d+)/configuration_plist/$',
        views.EnrollmentConfigurationView.as_view(response_type="plist"),
        name='enrollment_configuration_plist'),
    url(r'^configurations/(?P<configuration_pk>\d+)/enrollments/(?P<pk>\d+)/configuration_profile/$',
        views.EnrollmentConfigurationView.as_view(response_type="configuration_profile"),
        name='enrollment_configuration_profile'),

    # rules
    url(r'^configurations/(?P<configuration_pk>\d+)/rules/$',
        views.ConfigurationRulesView.as_view(),
        name='configuration_rules'),
    url(r'^configurations/(?P<configuration_pk>\d+)/rules/create/$',
        views.CreateConfigurationRuleView.as_view(),
        name='create_configuration_rule'),
    url(r'^configurations/(?P<configuration_pk>\d+)/rules/(?P<pk>\d+)/update/$',
        views.UpdateConfigurationRuleView.as_view(),
        name='update_configuration_rule'),
    url(r'^configurations/(?P<configuration_pk>\d+)/rules/(?P<pk>\d+)/delete/$',
        views.DeleteConfigurationRuleView.as_view(),
        name='delete_configuration_rule'),
    url(r'configurations/(?P<configuration_pk>\d+)/rules/pick_binary/$',
        views.PickRuleBinaryView.as_view(),
        name='pick_rule_binary'),
    url(r'configurations/(?P<configuration_pk>\d+)/rules/pick_bundle/$',
        views.PickRuleBundleView.as_view(),
        name='pick_rule_bundle'),
    url(r'configurations/(?P<configuration_pk>\d+)/rules/pick_certificate/$',
        views.PickRuleCertificateView.as_view(),
        name='pick_rule_certificate'),

    # API endpoints
    url(r'^sync/(?P<enrollment_secret>\S+)/preflight/(?P<machine_id>\S+)$',
        csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    url(r'^sync/(?P<enrollment_secret>\S+)/ruledownload/(?P<machine_id>\S+)$',
        csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    url(r'^sync/(?P<enrollment_secret>\S+)/eventupload/(?P<machine_id>\S+)$',
        csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    url(r'^sync/(?P<enrollment_secret>\S+)/postflight/(?P<machine_id>\S+)$',
        csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]


setup_menu_cfg = {
    'items': (
        ('configuration_list', 'Configurations'),
    )
}
