from django.urls import path, re_path

from . import views

app_name = "probes"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('create/', views.CreateProbeView.as_view(), name='create'),
    path('<int:pk>/', views.ProbeView.as_view(), name='probe'),
    path('<int:pk>/dashboard/', views.ProbeDashboardView.as_view(), name='probe_dashboard'),
    path('<int:pk>/dashboard/data/', views.ProbeDashboardDataView.as_view(), name='probe_dashboard_data'),
    path('<int:pk>/events/', views.ProbeEventsView.as_view(), name='probe_events'),
    path('<int:pk>/events/fetch/', views.FetchProbeEventsView.as_view(), name='fetch_probe_events'),
    path('<int:pk>/events/store_redirect/',
         views.ProbeEventsStoreRedirectView.as_view(),
         name='probe_events_store_redirect'),
    path('<int:pk>/update/', views.UpdateProbeView.as_view(), name='update'),
    path('<int:pk>/delete/', views.DeleteProbeView.as_view(), name='delete'),
    path('<int:pk>/clone/', views.CloneProbeView.as_view(), name='clone'),
    path('<int:pk>/review_update/', views.ReviewProbeUpdateView.as_view(), name='review_update'),
    path('<int:pk>/actions/<str:action>/edit/', views.EditActionView.as_view(), name='edit_action'),
    path('<int:pk>/actions/<str:action>/delete/', views.DeleteActionView.as_view(), name='delete_action'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/add/$',
            views.AddFilterView.as_view(), name='add_filter'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/update/$',
            views.UpdateFilterView.as_view(), name='update_filter'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/delete/$',
            views.DeleteFilterView.as_view(), name='delete_filter'),
    # feeds
    path('feeds/', views.FeedsView.as_view(), name="feeds"),
    path('feeds/create/', views.CreateFeedView.as_view(), name="create_feed"),
    path('feeds/<int:pk>/', views.FeedView.as_view(), name="feed"),
    path('feeds/<int:pk>/update/', views.UpdateFeedView.as_view(), name="update_feed"),
    path('feeds/<int:pk>/delete/', views.DeleteFeedView.as_view(), name="delete_feed"),
    path('feeds/<int:pk>/probes/<int:probe_id>/', views.FeedProbeView.as_view(), name="feed_probe"),
    path('feeds/<int:pk>/probes/<int:probe_id>/import/',
         views.ImportFeedProbeView.as_view(), name="import_feed_probe"),
]

main_menu_cfg = {
    'weight': 1,
    'items': (
        ('index', 'all probes', False, ('probes.view_probesource',)),
        ('feeds', 'feeds', False, ('probes.view_feed',)),
    ),
    'extra_context_links': (
        'probe_extra_links',
    )
}
