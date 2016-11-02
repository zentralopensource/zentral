from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^create/$', views.CreateProbeView.as_view(), name='create'),
    url(r'^(?P<pk>\d+)/$', views.ProbeView.as_view(), name='probe'),
    url(r'^(?P<pk>\d+)/events/$', views.ProbeEventsView.as_view(), name='probe_events'),
    url(r'^(?P<pk>\d+)/update/$', views.UpdateProbeView.as_view(), name='update'),
    url(r'^(?P<pk>\d+)/delete/$', views.DeleteProbeView.as_view(), name='delete'),
    url(r'^(?P<pk>\d+)/actions/(?P<action>\S+)/edit/$', views.EditActionView.as_view(), name='edit_action'),
    url(r'^(?P<pk>\d+)/actions/(?P<action>\S+)/delete/$', views.DeleteActionView.as_view(), name='delete_action'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/add/$',
        views.AddFilterView.as_view(), name='add_filter'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/update/$',
        views.UpdateFilterView.as_view(), name='update_filter'),
    url(r'^(?P<pk>\d+)/filters/(?P<section>(inventory|metadata|payload))/(?P<filter_id>\d+)/delete/$',
        views.DeleteFilterView.as_view(), name='delete_filter'),
]

main_menu_cfg = {
    'weight': 1,
    'items': (
        ('index', 'all probes'),
    ),
    'extra_context_links': (
        'probe_extra_links',
    )
}
