from django.urls import path
from . import views


app_name = "compliance_checks"
urlpatterns = [
    path('<int:pk>/redirect/', views.ComplianceCheckRedirectView.as_view(), name="redirect"),
]
