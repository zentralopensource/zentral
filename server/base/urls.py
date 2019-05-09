from django.urls import path, re_path
from . import views


app_name = "base"
urlpatterns = [
    re_path(r'^$', views.IndexView.as_view(), name='index'),
    re_path(r'^health_check/$', views.HealthCheckView.as_view(), name='health_check'),
    re_path(r'^app/(?P<app>\S+)/hist_data/(?P<interval>\S+)/(?P<bucket_number>\d+)/$',
            views.AppHistogramDataView.as_view(), name='app_hist_data'),
    path('task/<uuid:task_id>/',
         views.TaskResultView.as_view(), name='task_result'),
    path('task/<uuid:task_id>/download/',
         views.TaskResultFileDownloadView.as_view(), name='task_result_file_download'),
]
