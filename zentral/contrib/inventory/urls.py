from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^groups/$', views.GroupsView.as_view(), name='groups'),
    url(r'^groups/(?P<group_id>\d+)/machines/$', views.GroupMachinesView.as_view(), name='group_machines'),
    url(r'^business_units/$', views.MBUView.as_view(), name='mbu'),
    url(r'^business_units/review_merge/$', views.ReviewMBUMergeView.as_view(), name='review_mbu_merge'),
    url(r'^business_units/merge/$', views.MergeMBUView.as_view(), name='merge_mbu'),
    url(r'^business_units/create/$', views.CreateMBUView.as_view(), name='create_mbu'),
    url(r'^business_units/(?P<pk>\d+)/update/$', views.UpdateMBUView.as_view(), name='update_mbu'),
    url(r'^business_units/(?P<pk>\d+)/tags/$', views.MBUTagsView.as_view(), name='mbu_tags'),
    url(r'^business_units/(?P<pk>\d+)/tags/(?P<tag_id>\d+)/remove/$',
        views.RemoveMBUTagView.as_view(),
        name='remove_mbu_tag'),
    url(r'^business_units/(?P<pk>\d+)/machines/$', views.MBUMachinesView.as_view(), name='mbu_machines'),
    url(r'^business_units/(?P<pk>\d+)/api_enrollment/$',
        views.MBUAPIEnrollmentView.as_view(),
        name='mbu_api_enrollment'),
    url(r'^machine/(?P<serial_number>\S+)/events/$', views.MachineEventsView.as_view(), name='machine_events'),
    url(r'^machine/(?P<serial_number>\S+)/tags/$', views.MachineTagsView.as_view(), name='machine_tags'),
    url(r'^machine/(?P<serial_number>\S+)/tags/(?P<tag_id>\d+)/remove/$',
        views.RemoveMachineTagView.as_view(),
        name='remove_machine_tag'),
    url(r'^machine/(?P<serial_number>\S+)/archive/$', views.ArchiveMachineView.as_view(), name='archive_machine'),
    url(r'^machine/(?P<serial_number>\S+)/$', views.MachineView.as_view(), name='machine'),
    url(r'^probes/$', views.ProbesView.as_view(), name='probes'),
    url(r'^tags/$', views.TagsView.as_view(), name='tags'),
    url(r'^tags/(?P<pk>\d+)/update/$', views.UpdateTagView.as_view(), name='update_tag'),
    url(r'^tags/(?P<pk>\d+)/delete/$', views.DeleteTagView.as_view(), name='delete_tag'),
]


main_menu_cfg = {
    'weight': 0,
    'items': (
        ('index', 'Machines'),
        ('groups', 'Groups'),
        ('mbu', 'Business units'),
        ('probes', 'Probes'),
        ('tags', 'Tags'),
    )
}
