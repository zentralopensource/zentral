from django.urls import path
from .api_views import (ConfigurationDetail, ConfigurationList,
                        EnrollmentDetail, EnrollmentList, EnrollmentPackage,
                        ExportDistributedQueryResults,
                        PackView)


app_name = "osquery_api"
urlpatterns = [
    path('configurations/', ConfigurationList.as_view(), name="configurations"),
    path('configurations/<int:pk>/', ConfigurationDetail.as_view(), name="configuration"),
    path('enrollments/', EnrollmentList.as_view(), name="enrollments"),
    path('enrollments/<int:pk>/', EnrollmentDetail.as_view(), name="enrollment"),
    path('enrollments/<int:pk>/package/', EnrollmentPackage.as_view(), name="enrollment_package"),
    path('packs/<slug:slug>/', PackView.as_view(), name="pack"),
    path('runs/<int:pk>/results/export/',
         ExportDistributedQueryResults.as_view(), name="export_distributed_query_results"),
]
