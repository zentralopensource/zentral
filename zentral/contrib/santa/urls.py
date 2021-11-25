from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "santa"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name="index"),

    # configuration / enrollment
    path('configurations/',
         views.ConfigurationListView.as_view(),
         name='configuration_list'),
    path('configurations/create/',
         views.CreateConfigurationView.as_view(),
         name='create_configuration'),
    path('configurations/<int:pk>/',
         views.ConfigurationView.as_view(),
         name='configuration'),
    path('configurations/<int:pk>/events/',
         views.ConfigurationEventsView.as_view(),
         name='configuration_events'),
    path('configurations/<int:pk>/events/fetch/',
         views.FetchConfigurationEventsView.as_view(),
         name='fetch_configuration_events'),
    path('configurations/<int:pk>/events/store_redirect/',
         views.ConfigurationEventsStoreRedirectView.as_view(),
         name='configuration_events_store_redirect'),
    path('configurations/<int:pk>/update/',
         views.UpdateConfigurationView.as_view(),
         name='update_configuration'),
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(),
         name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/configuration_plist/',
         views.EnrollmentConfigurationView.as_view(response_type="plist"),
         name='enrollment_configuration_plist'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/configuration_profile/',
         views.EnrollmentConfigurationView.as_view(response_type="configuration_profile"),
         name='enrollment_configuration_profile'),

    # rules
    path('configurations/<int:configuration_pk>/rules/',
         views.ConfigurationRulesView.as_view(),
         name='configuration_rules'),
    path('configurations/<int:configuration_pk>/rules/create/',
         views.CreateConfigurationRuleView.as_view(),
         name='create_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/<int:pk>/update/',
         views.UpdateConfigurationRuleView.as_view(),
         name='update_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/<int:pk>/delete/',
         views.DeleteConfigurationRuleView.as_view(),
         name='delete_configuration_rule'),
    path('configurations/<int:configuration_pk>/rules/pick_binary/',
         views.PickRuleBinaryView.as_view(),
         name='pick_rule_binary'),
    path('configurations/<int:configuration_pk>/rules/pick_bundle/',
         views.PickRuleBundleView.as_view(),
         name='pick_rule_bundle'),
    path('configurations/<int:configuration_pk>/rules/pick_certificate/',
         views.PickRuleCertificateView.as_view(),
         name='pick_rule_certificate'),

    # targets
    path('targets/', views.TargetsView.as_view(), name="targets"),
    path('targets/binaries/<str:sha256>/', views.BinaryView.as_view(), name="binary"),
    path('targets/bundles/<str:sha256>/', views.BundleView.as_view(), name="bundle"),
    path('targets/certificates/<str:sha256>/', views.CertificateView.as_view(), name="certificate"),

    # API
    path('sync/<str:enrollment_secret>/preflight/<str:machine_id>',
         csrf_exempt(views.PreflightView.as_view()), name='preflight'),
    path('sync/<str:enrollment_secret>/ruledownload/<str:machine_id>',
         csrf_exempt(views.RuleDownloadView.as_view()), name='ruledownload'),
    path('sync/<str:enrollment_secret>/eventupload/<str:machine_id>',
         csrf_exempt(views.EventUploadView.as_view()), name='eventupload'),
    path('sync/<str:enrollment_secret>/postflight/<str:machine_id>',
         csrf_exempt(views.PostflightView.as_view()), name='postflight'),
]


setup_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('santa',)),
        ('configuration_list', 'Configurations', False, ('santa.view_configuration',)),
        ('targets', 'Targets', False, ('santa.view_target',)),
    )
}
