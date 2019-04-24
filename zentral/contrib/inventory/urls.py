from django.conf.urls import url

from . import views

app_name = "inventory"
urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^groups/$', views.GroupsView.as_view(), name='groups'),
    url(r'^groups/(?P<group_id>\d+)/machines/$', views.GroupMachinesView.as_view(), name='group_machines'),
    url(r'^business_units/$', views.MBUView.as_view(), name='mbu'),
    url(r'^business_units/review_merge/$', views.ReviewMBUMergeView.as_view(), name='review_mbu_merge'),
    url(r'^business_units/merge/$', views.MergeMBUView.as_view(), name='merge_mbu'),
    url(r'^business_units/create/$', views.CreateMBUView.as_view(), name='create_mbu'),
    url(r'^business_units/(?P<pk>\d+)/update/$', views.UpdateMBUView.as_view(), name='update_mbu'),
    url(r'^business_units/(?P<pk>\d+)/delete/$', views.DeleteMBUView.as_view(), name='delete_mbu'),
    url(r'^business_units/(?P<pk>\d+)/tags/$', views.MBUTagsView.as_view(), name='mbu_tags'),
    url(r'^business_units/(?P<pk>\d+)/tags/(?P<tag_id>\d+)/remove/$',
        views.RemoveMBUTagView.as_view(),
        name='remove_mbu_tag'),
    url(r'^business_units/(?P<pk>\d+)/machines/$', views.MBUMachinesView.as_view(), name='mbu_machines'),
    url(r'^business_units/(?P<pk>\d+)/detach_bu/(?P<bu_id>\d+)/$', views.DetachBUView.as_view(), name='detach_bu'),
    url(r'^business_units/(?P<pk>\d+)/api_enrollment/$',
        views.MBUAPIEnrollmentView.as_view(),
        name='mbu_api_enrollment'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/events/$',
        views.MachineEventsView.as_view(),
        name='machine_events'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/macos_app_instances/$',
        views.MachineMacOSAppInstancesView.as_view(),
        name='machine_macos_app_instances'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/incidents/$',
        views.MachineIncidentsView.as_view(),
        name='machine_incidents'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/tags/$', views.MachineTagsView.as_view(), name='machine_tags'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/tags/(?P<tag_id>\d+)/remove/$',
        views.RemoveMachineTagView.as_view(),
        name='remove_machine_tag'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/archive/$',
        views.ArchiveMachineView.as_view(),
        name='archive_machine'),
    url(r'^machine/(?P<urlsafe_serial_number>\S+)/$', views.MachineView.as_view(), name='machine'),
    url(r'^tags/$', views.TagsView.as_view(), name='tags'),
    url(r'^tags/create/$', views.CreateTagView.as_view(), name='create_tag'),
    url(r'^tags/(?P<pk>\d+)/update/$', views.UpdateTagView.as_view(), name='update_tag'),
    url(r'^tags/(?P<pk>\d+)/delete/$', views.DeleteTagView.as_view(), name='delete_tag'),
    url(r'^taxonomies/create/$', views.CreateTaxonomyView.as_view(), name='create_taxonomy'),
    url(r'^taxonomies/(?P<pk>\d+)/update/$', views.UpdateTaxonomyView.as_view(), name='update_taxonomy'),
    url(r'^taxonomies/(?P<pk>\d+)/delete/$', views.DeleteTaxonomyView.as_view(), name='delete_taxonomy'),
    url(r'^macos_apps/$', views.MacOSAppsView.as_view(), name='macos_apps'),
    url(r'^macos_apps/(?P<pk>\d+)/$', views.MacOSAppView.as_view(), name='macos_app'),
    url(r'^macos_apps/(?P<pk>\d+)/instance/(?P<osx_app_instance_id>\d+)/machines/$',
        views.OSXAppInstanceMachinesView.as_view(),
        name='macos_app_instance_machines'),

    # API
    url(r'^prometheus_metrics/$',
        views.PrometheusMetricsView.as_view(),
        name='prometheus_metrics'),
]

main_menu_cfg = {
    'weight': 0,
    'items': (
        ('index', 'Machines'),
        ('groups', 'Groups'),
        ('mbu', 'Business units'),
        ('macos_apps', 'macOS applications'),
        ('tags', 'Tags'),
    )
}
