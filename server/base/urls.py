from django.conf.urls import url

from . import views

app_name = "base"
urlpatterns = [
    url(r'^$', views.IndexView.as_view(), name='index'),
    url(r'^health_check/$', views.HealthCheckView.as_view(), name='health_check'),
    url(r'^app/(?P<app>\S+)/hist_data/(?P<interval>\S+)/(?P<bucket_number>\d+)/$',
        views.AppHistogramDataView.as_view(), name='app_hist_data'),
]
