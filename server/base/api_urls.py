from django.urls import path
from .api_views import TaskResultFileDownloadView, TaskResultView


app_name = "base_api"
urlpatterns = [
    path('task_result/<uuid:task_id>/',
         TaskResultView.as_view(), name='task_result'),
    path('task_result/<uuid:task_id>/download/',
         TaskResultFileDownloadView.as_view(), name='task_result_file_download'),
]
