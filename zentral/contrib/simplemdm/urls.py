from django.conf.urls import url
from . import views

app_name = "simplemdm"
urlpatterns = [
    url(r'instances/$',
        views.SimpleMDMInstancesView.as_view(),
        name="simplemdm_instances"),
    url(r'instances/create/$',
        views.CreateSimpleMDMInstanceView.as_view(),
        name="create_simplemdm_instance"),
    url(r'instances/(?P<pk>\d+)/$',
        views.SimpleMDMInstanceView.as_view(),
        name="simplemdm_instance"),
    url(r'instances/(?P<pk>\d+)/update/$',
        views.UpdateSimpleMDMInstanceView.as_view(),
        name="update_simplemdm_instance"),
    url(r'instances/(?P<pk>\d+)/delete/$',
        views.DeleteSimpleMDMInstanceView.as_view(),
        name="delete_simplemdm_instance"),
    url(r'instances/(?P<pk>\d+)/create_app/$',
        views.CreateSimpleMDMAppView.as_view(),
        name="create_simplemdm_app"),
    url(r'instances/(?P<instance_pk>\d+)/delete_app/(?P<pk>\d+)/$',
        views.DeleteSimpleMDMAppView.as_view(),
        name="delete_simplemdm_app"),
]


setup_menu_cfg = {
    'items': (
        ('simplemdm_instances', 'Instances'),
    )
}
