from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "munki"
urlpatterns = [
    # configuration
    path('configurations/', views.ConfigurationListView.as_view(), name='configurations'),
    path('configurations/create/', views.CreateConfigurationView.as_view(), name='create_configuration'),
    path('configurations/<int:pk>/', views.ConfigurationView.as_view(), name='configuration'),
    path('configurations/<int:pk>/update/', views.UpdateConfigurationView.as_view(), name='update_configuration'),

    # enrollment
    path('configurations/<int:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(), name='create_enrollment'),
    path('configurations/<int:configuration_pk>/enrollments/<int:pk>/bump_version/',
         views.EnrollmentBumpVersionView.as_view(),
         name='bump_enrollment_version'),

    # install probe
    path('install_probes/create/',
         views.CreateInstallProbeView.as_view(), name='create_install_probe'),
    path('install_probes/<int:probe_id>/update/',
         views.UpdateInstallProbeView.as_view(), name='update_install_probe'),

    # API
    path('enroll/', csrf_exempt(views.EnrollView.as_view()), name='enroll'),
    path('job_details/', csrf_exempt(views.JobDetailsView.as_view()), name="job_details"),
    path('post_job/', csrf_exempt(views.PostJobView.as_view()), name="post_job")
]


setup_menu_cfg = {
    'items': (
        ('configurations', 'Configurations', False, ('munki.view_configuration',)),
    )
}
