from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

app_name = "jamf"
urlpatterns = [
    # setup > jamf instances
    url(r'instances/$', views.JamfInstancesView.as_view(), name="jamf_instances"),
    url(r'instances/create/$', views.CreateJamfInstanceView.as_view(), name="create_jamf_instance"),
    url(r'instances/(?P<pk>\d+)/$', views.JamfInstanceView.as_view(), name="jamf_instance"),
    url(r'instances/(?P<pk>\d+)/setup/$', views.SetupJamfInstanceView.as_view(), name="setup_jamf_instance"),
    url(r'instances/(?P<pk>\d+)/update/$', views.UpdateJamfInstanceView.as_view(), name="update_jamf_instance"),
    url(r'instances/(?P<pk>\d+)/delete/$', views.DeleteJamfInstanceView.as_view(), name="delete_jamf_instance"),
    url(r'instances/(?P<pk>\d+)/tag_configs/create/$',
        views.CreateTagConfigView.as_view(),
        name="create_tag_config"),
    url(r'instances/(?P<ji_pk>\d+)/tag_configs/(?P<pk>\d+)/update/$',
        views.UpdateTagConfigView.as_view(),
        name="update_tag_config"),
    url(r'instances/(?P<ji_pk>\d+)/tag_configs/(?P<pk>\d+)/delete/$',
        views.DeleteTagConfigView.as_view(),
        name="delete_tag_config"),
    # API
    url(r'^post_event/(?P<secret>\S+)/$', csrf_exempt(views.PostEventView.as_view()), name='post_event'),
]


setup_menu_cfg = {
    'items': (
        ('jamf_instances', 'jamf instances'),
    )
}
