from django.urls import path
from .api_views import ComplianceCheckDetail, ComplianceCheckList, MachineStatusList


app_name = "compliance_checks_api"
urlpatterns = [
    path('compliance_checks/', ComplianceCheckList.as_view(), name="compliance_checks"),
    path('compliance_checks/<int:pk>/', ComplianceCheckDetail.as_view(), name="compliance_check"),
    path('machine_statuses/', MachineStatusList.as_view(), name="machine_statuses"),
]
