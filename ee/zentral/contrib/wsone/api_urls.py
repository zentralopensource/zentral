from django.urls import path
from .api_views import InstanceDetail, InstanceList, StartInstanceSync


app_name = "wsone_api"
urlpatterns = [
    path('instances/', InstanceList.as_view(), name="instances"),
    path('instances/<int:pk>/', InstanceDetail.as_view(), name="instance"),
    path('instances/<int:pk>/sync/', StartInstanceSync.as_view(), name="start_instance_sync"),
]
