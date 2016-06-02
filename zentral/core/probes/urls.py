from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^create/$', views.CreateProbeView.as_view(), name='create'),
    url(r'^(?P<pk>\d+)/$', views.ProbeView.as_view(), name='probe'),
    url(r'^(?P<pk>\d+)/update/$', views.UpdateProbeView.as_view(), name='update'),
    url(r'^(?P<pk>\d+)/delete/$', views.DeleteProbeView.as_view(), name='delete'),
]

main_menu_cfg = {
    'weight': 1,
    'items': (
        ('index', 'Probes'),
        ('create', 'New probe'),
    )
}
