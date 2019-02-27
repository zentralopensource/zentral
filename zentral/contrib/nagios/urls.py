from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "nagios"
urlpatterns = [
    # setup > nagios instances
    url(r'instances/$', views.NagiosInstancesView.as_view(), name="nagios_instances"),
    url(r'instances/create/$', views.CreateNagiosInstanceView.as_view(), name="create_nagios_instance"),
    url(r'instances/(?P<pk>\d+)/download_event_handler/$',
        views.DownloadNagiosInstanceEventHandlerView.as_view(),
        name="download_nagios_instance_event_handler"),
    url(r'instances/(?P<pk>\d+)/update/$', views.UpdateNagiosInstanceView.as_view(), name="update_nagios_instance"),
    url(r'instances/(?P<pk>\d+)/delete/$', views.DeleteNagiosInstanceView.as_view(), name="delete_nagios_instance"),
    # API
    url(r'^post_event/$', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]


setup_menu_cfg = {
    'items': (
        ('nagios_instances', 'nagios instances'),
    )
}
