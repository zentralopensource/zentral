from django.urls import re_path
from . import views


app_name = "base"
urlpatterns = [
    re_path(r'^$', views.IndexView.as_view(), name='index'),
    re_path(r'^health_check/$', views.HealthCheckView.as_view(), name='health_check'),
    re_path(r'^app/(?P<app>\S+)/hist_data/(?P<interval>\S+)/(?P<bucket_number>\d+)/$',
            views.AppHistogramDataView.as_view(), name='app_hist_data'),
]
