from django.urls import path
from .api_views import UpdateProbeFeedView


app_name = "probes_api"
urlpatterns = [
    path('feeds/<int:pk>/', UpdateProbeFeedView.as_view(), name="feed"),
]
