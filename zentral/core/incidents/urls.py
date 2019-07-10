from django.conf.urls import url

from . import views

app_name = "incidents"
urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^(?P<pk>\d+)/$', views.IncidentView.as_view(), name='incident'),
    url(r'^(?P<pk>\d+)/update/$', views.UpdateIncidentView.as_view(), name='update_incident'),
    url(r'^(?P<pk>\d+)/events/$', views.IncidentEventsView.as_view(), name='incident_events'),
    url(r'^(?P<incident_pk>\d+)/machine_incident/(?P<pk>\d+)/update/$',
        views.UpdateMachineIncidentView.as_view(), name='update_machine_incident'),
    url(r'^prometheus_metrics/$',
        views.PrometheusMetricsView.as_view(),
        name='prometheus_metrics'),
]

main_menu_cfg = {
    'weight': 2,
    'items': (
        ('index', 'all incidents'),
    ),
}
