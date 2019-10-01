from django.conf.urls import url

from . import views

app_name = "probes"
urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^create/$', views.CreateProbeView.as_view(), name='create'),
    url(r'^(?P<pk>\d+)/$', views.ProbeView.as_view(), name='probe'),
    url(r'^(?P<pk>\d+)/dashboard/$', views.ProbeDashboardView.as_view(), name='probe_dashboard'),
    url(r'^(?P<pk>\d+)/dashboard/data/$', views.ProbeDashboardDataView.as_view(), name='probe_dashboard_data'),
    url(r'^(?P<pk>\d+)/events/$', views.ProbeEventsView.as_view(), name='probe_events'),
    url(r'^(?P<pk>\d+)/update/$', views.UpdateProbeView.as_view(), name='update'),
    url(r'^(?P<pk>\d+)/delete/$', views.DeleteProbeView.as_view(), name='delete'),
    url(r'^(?P<pk>\d+)/clone/$', views.CloneProbeView.as_view(), name='clone'),
    url(r'^(?P<pk>\d+)/review_update/$', views.ReviewProbeUpdateView.as_view(), name='review_update'),
    url(r'^(?P<pk>\d+)/actions/(?P<action>\S+)/edit/$', views.EditActionView.as_view(), name='edit_action'),
    url(r'^(?P<pk>\d+)/actions/(?P<action>\S+)/delete/$', views.DeleteActionView.as_view(), name='delete_action'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/add/$',
        views.AddFilterView.as_view(), name='add_filter'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/update/$',
        views.UpdateFilterView.as_view(), name='update_filter'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/delete/$',
        views.DeleteFilterView.as_view(), name='delete_filter'),
    # feeds
    url(r'^feeds/$', views.FeedsView.as_view(), name="feeds"),
    url(r'^feeds/add/$', views.AddFeedView.as_view(), name="add_feed"),
    url(r'^feeds/(?P<pk>\d+)/$', views.FeedView.as_view(), name="feed"),
    url(r'^feeds/(?P<pk>\d+)/sync/$', views.SyncFeedView.as_view(), name="sync_feed"),
    url(r'^feeds/(?P<pk>\d+)/delete/$', views.DeleteFeedView.as_view(), name="delete_feed"),
    url(r'^feeds/(?P<pk>\d+)/probes/(?P<probe_id>\d+)/$', views.FeedProbeView.as_view(), name="feed_probe"),
    url(r'^feeds/(?P<pk>\d+)/probes/(?P<probe_id>\d+)/import/$',
        views.ImportFeedProbeView.as_view(), name="import_feed_probe"),
]

main_menu_cfg = {
    'weight': 1,
    'items': (
        ('index', 'all probes'),
        ('feeds', 'feeds'),
    ),
    'extra_context_links': (
        'probe_extra_links',
    )
}
