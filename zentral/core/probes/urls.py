from django.urls import path, re_path

from . import views

app_name = "probes"
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('create/', views.CreateProbeView.as_view(), name='create'),
    path('<int:pk>/', views.ProbeView.as_view(), name='probe'),
    path('<int:pk>/events/', views.ProbeEventsView.as_view(), name='probe_events'),
    path('<int:pk>/events/fetch/', views.FetchProbeEventsView.as_view(), name='fetch_probe_events'),
    path('<int:pk>/events/store_redirect/',
         views.ProbeEventsStoreRedirectView.as_view(),
         name='probe_events_store_redirect'),
    path('<int:pk>/update/', views.UpdateProbeView.as_view(), name='update'),
    path('<int:pk>/delete/', views.DeleteProbeView.as_view(), name='delete'),
    path('<int:pk>/clone/', views.CloneProbeView.as_view(), name='clone'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/add/$',
            views.AddFilterView.as_view(), name='add_filter'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/update/$',
            views.UpdateFilterView.as_view(), name='update_filter'),
    re_path(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/delete/$',
            views.DeleteFilterView.as_view(), name='delete_filter'),
]

pinned_menu_cfg = {
    'weight': 1,
    'items': (
        ('index', 'all probes', False, ('probes.view_probesource',)),
    )
}
