from django.urls import path
from .metrics_views import MetricsView


app_name = "realms_metrics"
urlpatterns = [
    path("", MetricsView.as_view(), name="all")
]
