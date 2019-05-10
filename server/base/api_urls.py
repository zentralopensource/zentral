from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import TaskResultFileDownloadView, TaskResultView


app_name = "base_api"
urlpatterns = [
    path('task_result/<uuid:task_id>/',
         TaskResultView.as_view(), name='task_result'),
    path('task_result/<uuid:task_id>/download/',
         TaskResultFileDownloadView.as_view(), name='task_result_file_download'),
]


urlpatterns = format_suffix_patterns(urlpatterns)
