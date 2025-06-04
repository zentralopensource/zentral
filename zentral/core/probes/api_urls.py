from django.urls import path
from .api_views import ActionDetail, ActionList, ProbeDetail, ProbeList


app_name = "probes_api"
urlpatterns = [
    path('actions/', ActionList.as_view(), name="actions"),
    path('actions/<uuid:pk>/', ActionDetail.as_view(), name="action"),
    path('probes/', ProbeList.as_view(), name="probes"),
    path('probes/<int:pk>/', ProbeDetail.as_view(), name="probe"),
]
