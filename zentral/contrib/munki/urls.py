from django.urls import path
from . import views

app_name = "munki"
urlpatterns = [
    # index
    path('', views.IndexView.as_view(), name="index"),

    # configuration
    path('configurations/', views.ConfigurationListView.as_view(), name='configurations'),
    path('configurations/create/', views.CreateConfigurationView.as_view(), name='create_configuration'),
    path('configurations/<int:pk>/', views.ConfigurationView.as_view(), name='configuration'),
    path('configurations/<int:pk>/events/', views.ConfigurationEventsView.as_view(), name='configuration_events'),
    path('configurations/<int:pk>/events/fetch/', 
         views.FetchConfigurationEventsView.as_view(),
         name='fetch_configuration_events'),
    path('configurations/<int:pk>/events/store_redirect/',
         views.ConfigurationEventsStoreRedirectView.as_view(),
         name='configuration_events_store_redirect'),

    path('configurations/<int:pk>/update/', views.UpdateConfigurationView.as_view(), name='update_configuration'),

    # enrollment
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(), name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/delete/',
         views.DeleteEnrollmentView.as_view(),
         name='delete_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/bump_version/',
         views.EnrollmentBumpVersionView.as_view(),
         name='bump_enrollment_version'),

    # script check
    path('script_checks/', views.ScriptCheckListView.as_view(), name='script_checks'),
    path('script_checks/create/', views.CreateScriptCheckView.as_view(), name='create_script_check'),
    path('script_checks/<int:pk>/', views.ScriptCheckView.as_view(), name='script_check'),
    path('script_checks/<int:pk>/update/', views.UpdateScriptCheckView.as_view(), name='update_script_check'),
    path('script_checks/<int:pk>/delete/', views.DeleteScriptCheckView.as_view(), name='delete_script_check'),
    path('script_checks/<int:pk>/events/', views.ScriptCheckEventsView.as_view(), name='script_check_events'),
    path('script_checks/<int:pk>/events/fetch/',
         views.FetchScriptCheckEventsView.as_view(),
         name='fetch_script_check_events'),
    path('script_checks/<int:pk>/events/store_redirect/',
         views.ScriptCheckEventsStoreRedirectView.as_view(),
         name='script_check_events_store_redirect'),

    # install probe
    path('install_probes/create/',
         views.CreateInstallProbeView.as_view(), name='create_install_probe'),
    path('install_probes/<int:probe_id>/update/',
         views.UpdateInstallProbeView.as_view(), name='update_install_probe'),

    # terraform
    path('terraform_export/',
         views.TerraformExportView.as_view(),
         name='terraform_export'),
]


modules_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('munki.index',)),
        ('configurations', 'Configurations', False, ('munki.view_configuration',)),
        ('script_checks', 'Script checks', False, ('munki.view_scriptcheck',)),
    ),
    'weight': 30,
}
