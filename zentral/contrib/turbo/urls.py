from django.urls import path
from . import views

app_name = "turbo"
urlpatterns = [
    # overview
    path('', views.IndexView.as_view(), name='index'),

    # configuration
    path('configurations/', views.ConfigurationListView.as_view(), name='configurations'),
    path('configurations/create/', views.CreateConfigurationView.as_view(), name='create_configuration'),
    path('configurations/<uuid:pk>/', views.ConfigurationView.as_view(), name='configuration'),
    path('configurations/<uuid:pk>/update/', views.UpdateConfigurationView.as_view(), name='update_configuration'),
    path('configurations/<uuid:pk>/delete/', views.DeleteConfigurationView.as_view(), name='delete_configuration'),

    # enrollment
    path('configurations/<uuid:pk>/enrollments/create/',
         views.CreateEnrollmentView.as_view(), name='create_enrollment'),
    path('configurations/<uuid:configuration_pk>/enrollments/<int:pk>/delete/',
         views.DeleteEnrollmentView.as_view(),
         name='delete_enrollment'),
    path('configurations/<uuid:configuration_pk>/enrollments/<int:pk>/bump_version/',
         views.EnrollmentBumpVersionView.as_view(),
         name='bump_enrollment_version'),

    # enrolled machine
    path('enrolled_machines/', views.EnrolledMachineListView.as_view(), name='enrolled_machines'),
    path('enrolled_machines/<str:serial_number>/',
         views.EnrolledMachineDetailView.as_view(), name='enrolled_machine'),
    path('enrolled_machines/<str:serial_number>/schedule/',
         views.ScheduleMachineOneTimeJobView.as_view(), name='schedule_machine_one_time_job'),

    # script
    path('scripts/', views.ScriptListView.as_view(), name='scripts'),
    path('scripts/create/', views.CreateScriptView.as_view(), name='create_script'),
    path('scripts/<uuid:pk>/', views.ScriptView.as_view(), name='script'),
    path('scripts/<uuid:pk>/update/', views.UpdateScriptView.as_view(), name='update_script'),
    path('scripts/<uuid:pk>/delete/', views.DeleteScriptView.as_view(), name='delete_script'),

    # mSCP check
    path('mscp_checks/', views.MSCPCheckListView.as_view(), name='mscp_checks'),
    path('mscp_checks/create/', views.CreateMSCPCheckView.as_view(), name='create_mscp_check'),
    path('mscp_checks/<uuid:pk>/', views.MSCPCheckView.as_view(), name='mscp_check'),
    path('mscp_checks/<uuid:pk>/update/', views.UpdateMSCPCheckView.as_view(), name='update_mscp_check'),
    path('mscp_checks/<uuid:pk>/delete/', views.DeleteMSCPCheckView.as_view(), name='delete_mscp_check'),

    # recurring job
    path('recurring_jobs/', views.RecurringJobListView.as_view(), name='recurring_jobs'),
    path('configurations/<uuid:configuration_pk>/recurring_jobs/create/',
         views.CreateRecurringJobView.as_view(), name='create_recurring_job'),
    path('configurations/<uuid:configuration_pk>/recurring_jobs/<uuid:pk>/update/',
         views.UpdateRecurringJobView.as_view(), name='update_recurring_job'),
    path('configurations/<uuid:configuration_pk>/recurring_jobs/<uuid:pk>/delete/',
         views.DeleteRecurringJobView.as_view(), name='delete_recurring_job'),

    # one-time job
    path('one_time_jobs/', views.OneTimeJobListView.as_view(), name='one_time_jobs'),
    path('configurations/<uuid:configuration_pk>/one_time_jobs/create/',
         views.CreateOneTimeJobView.as_view(), name='create_one_time_job'),
    path('configurations/<uuid:configuration_pk>/one_time_jobs/<uuid:pk>/update/',
         views.UpdateOneTimeJobView.as_view(), name='update_one_time_job'),
    path('configurations/<uuid:configuration_pk>/one_time_jobs/<uuid:pk>/delete/',
         views.DeleteOneTimeJobView.as_view(), name='delete_one_time_job'),
]


modules_menu_cfg = {
    'items': (
        ('index', 'Overview', False, ('turbo',)),
        ('configurations', 'Configurations', False, ('turbo.view_configuration',)),
        ('enrolled_machines', 'Enrolled machines', False, ('turbo.view_enrolledmachine',)),
        ('scripts', 'Scripts', False, ('turbo.view_script',)),
        ('mscp_checks', 'mSCP checks', False, ('turbo.view_mscpcheck',)),
        ('recurring_jobs', 'Recurring jobs', False, ('turbo.view_recurringjob',)),
        ('one_time_jobs', 'One-time jobs', False, ('turbo.view_onetimejob',)),
    ),
    'weight': 35,
}
