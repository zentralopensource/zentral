from django.urls import path
from . import views


app_name = "inventory"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),

    # groups
    path('groups/', views.GroupsView.as_view(), name='groups'),
    path('groups/<int:group_id>/machines/', views.GroupMachinesView.as_view(), name='group_machines'),

    # business units
    path('business_units/', views.MBUView.as_view(), name='mbu'),
    path('business_units/review_merge/', views.ReviewMBUMergeView.as_view(), name='review_mbu_merge'),
    path('business_units/merge/', views.MergeMBUView.as_view(), name='merge_mbu'),
    path('business_units/create/', views.CreateMBUView.as_view(), name='create_mbu'),
    path('business_units/<int:pk>/update/', views.UpdateMBUView.as_view(), name='update_mbu'),
    path('business_units/<int:pk>/delete/', views.DeleteMBUView.as_view(), name='delete_mbu'),
    path('business_units/<int:pk>/tags/', views.MBUTagsView.as_view(), name='mbu_tags'),
    path('business_units/<int:pk>/tags/<int:tag_id>/remove/',
         views.RemoveMBUTagView.as_view(),
         name='remove_mbu_tag'),
    path('business_units/<int:pk>/machines/', views.MBUMachinesView.as_view(), name='mbu_machines'),
    path('business_units/<int:pk>/detach_bu/<int:bu_id>/', views.DetachBUView.as_view(), name='detach_bu'),
    path('business_units/<int:pk>/api_enrollment/',
         views.MBUAPIEnrollmentView.as_view(),
         name='mbu_api_enrollment'),

    # machines
    path('machine/<str:urlsafe_serial_number>/events/',
         views.MachineEventsView.as_view(),
         name='machine_events'),
    path('machine/<str:urlsafe_serial_number>/events/fetch/',
         views.FetchMachineEventsView.as_view(),
         name='fetch_machine_events'),
    path('machine/<str:urlsafe_serial_number>/events/store_redirect/',
         views.MachineEventsStoreRedirectView.as_view(),
         name='machine_events_store_redirect'),
    path('machine/<str:urlsafe_serial_number>/macos_app_instances/',
         views.MachineMacOSAppInstancesView.as_view(),
         name='machine_macos_app_instances'),
    path('machine/<str:urlsafe_serial_number>/program_instances/',
         views.MachineProgramInstancesView.as_view(),
         name='machine_program_instances'),
    path('machine/<str:urlsafe_serial_number>/deb_packages/',
         views.MachineDebPackagesView.as_view(),
         name='machine_deb_packages'),
    path('machine/<str:urlsafe_serial_number>/android_apps/',
         views.MachineAndroidAppsView.as_view(),
         name='machine_android_apps'),
    path('machine/<str:urlsafe_serial_number>/ios_apps/',
         views.MachineIOSAppsView.as_view(),
         name='machine_ios_apps'),
    path('machine/<str:urlsafe_serial_number>/profiles/',
         views.MachineProfilesView.as_view(),
         name='machine_profiles'),
    path('machine/<str:urlsafe_serial_number>/incidents/',
         views.MachineIncidentsView.as_view(),
         name='machine_incidents'),
    path('machine/<str:urlsafe_serial_number>/tags/', views.MachineTagsView.as_view(), name='machine_tags'),
    path('machine/<str:urlsafe_serial_number>/tags/<int:tag_id>/remove/',
         views.RemoveMachineTagView.as_view(),
         name='remove_machine_tag'),
    path('machine/<str:urlsafe_serial_number>/archive/',
         views.ArchiveMachineView.as_view(),
         name='archive_machine'),
    path('machine/<str:urlsafe_serial_number>/heartbeats/',
         views.MachineHeartbeatsView.as_view(),
         name='machine_heartbeats'),
    path('machine/<str:urlsafe_serial_number>/', views.MachineView.as_view(), name='machine'),

    # compliance checks
    path('compliance_checks/', views.ComplianceChecksView.as_view(), name='compliance_checks'),
    path('compliance_checks/create/', views.CreateComplianceCheckView.as_view(), name='create_compliance_check'),
    path('compliance_checks/<int:pk>/', views.ComplianceCheckView.as_view(), name='compliance_check'),
    path('compliance_checks/<int:pk>/update/',
         views.UpdateComplianceCheckView.as_view(),
         name='update_compliance_check'),
    path('compliance_checks/<int:pk>/delete/',
         views.DeleteComplianceCheckView.as_view(),
         name='delete_compliance_check'),
    path('compliance_checks/<int:pk>/events/',
         views.ComplianceCheckEventsView.as_view(),
         name='compliance_check_events'),
    path('compliance_checks/<int:pk>/events/fetch/',
         views.FetchComplianceCheckEventsView.as_view(),
         name='fetch_compliance_check_events'),
    path('compliance_checks/<int:pk>/events/store_redirect/',
         views.ComplianceCheckEventsStoreRedirectView.as_view(),
         name='compliance_check_events_store_redirect'),
    path('compliance_checks/devtool/', views.ComplianceCheckDevToolView.as_view(), name='compliance_check_devtool'),

    # tags
    path('tags/', views.TagsView.as_view(), name='tags'),
    path('tags/create/', views.CreateTagView.as_view(), name='create_tag'),
    path('tags/<int:pk>/update/', views.UpdateTagView.as_view(), name='update_tag'),
    path('tags/<int:pk>/delete/', views.DeleteTagView.as_view(), name='delete_tag'),
    path('taxonomies/create/', views.CreateTaxonomyView.as_view(), name='create_taxonomy'),
    path('taxonomies/<int:pk>/update/', views.UpdateTaxonomyView.as_view(), name='update_taxonomy'),
    path('taxonomies/<int:pk>/delete/', views.DeleteTaxonomyView.as_view(), name='delete_taxonomy'),

    # macOS apps
    path('macos_apps/', views.MacOSAppsView.as_view(), name='macos_apps'),
    path('macos_apps/<int:pk>/', views.MacOSAppView.as_view(), name='macos_app'),
    path('macos_apps/<int:pk>/instance/<int:osx_app_instance_id>/machines/',
         views.OSXAppInstanceMachinesView.as_view(),
         name='macos_app_instance_machines'),
]

main_menu_cfg = {
    'weight': 0,
    'items': (
        ('index', 'Machines', False, ("inventory.view_machinesnapshot",)),
        ('groups', 'Groups', False, ("inventory.view_machinegroup",)),
        ('mbu', 'Business units', False, ("inventory.view_metabusinessunit",)),
        ('macos_apps', 'macOS applications', False, ("inventory.view_osxapp", "inventory.view_osxappinstance")),
        ('compliance_checks', 'Compliance checks', False, ("inventory.view_jmespathcheck",)),
        ('tags', 'Tags', False, ("inventory.view_tag",)),
    )
}
