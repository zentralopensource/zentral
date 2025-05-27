from django.urls import path
from .api_views import ActionDetail, ActionList, UpdateProbeFeedView


app_name = "probes_api"
urlpatterns = [
    path('actions/', ActionList.as_view(), name="actions"),
    path('actions/<uuid:pk>/', ActionDetail.as_view(), name="action"),
    path('feeds/<int:pk>/', UpdateProbeFeedView.as_view(), name="feed"),
]
