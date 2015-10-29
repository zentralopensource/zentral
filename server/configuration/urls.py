from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^/probes/(?P<probe_key>\S+)/$', views.ProbeView.as_view(), name='probe'),
]
