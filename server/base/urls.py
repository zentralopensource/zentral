from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^health_check/$', views.HealthCheckView.as_view(), name='health_check'),
]
