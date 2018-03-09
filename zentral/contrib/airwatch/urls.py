from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'instances/$',
        views.AirwatchInstancesView.as_view(),
        name="airwatch_instances"),
    url(r'instances/create/$',
        views.CreateAirwatchInstanceView.as_view(),
        name="create_airwatch_instance"),
    url(r'instances/(?P<pk>\d+)/$',
        views.AirwatchInstanceView.as_view(),
        name="airwatch_instance"),
    url(r'instances/(?P<pk>\d+)/update/$',
        views.UpdateAirwatchInstanceView.as_view(),
        name="update_airwatch_instance"),
    url(r'instances/(?P<pk>\d+)/delete/$',
        views.DeleteAirwatchInstanceView.as_view(),
        name="delete_airwatch_instance"),
    url(r'instances/(?P<pk>\d+)/create_app/$',
        views.CreateAirwatchAppView.as_view(),
        name="create_airwatch_app"),
]


setup_menu_cfg = {
    'items': (
        ('airwatch_instances', 'Airwatch instances'),
    )
}
