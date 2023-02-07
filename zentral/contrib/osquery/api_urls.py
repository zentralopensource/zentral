from django.urls import path
from .api_views import (ConfigurationDetail, ConfigurationList,
                        EnrollmentDetail, EnrollmentList,
                        EnrollmentPackage, EnrollmentPowershellScript, EnrollmentScript,
                        ExportDistributedQueryResults,
                        PackView, QueryList, QueryDetail, AutomaticTableConstructionList,
                        AutomaticTableConstructionDetail, FileCategoryList, FileCategoryDetail, ConfigurationPackList,
                        ConfigurationPackDetail)


app_name = "osquery_api"
urlpatterns = [
    path('atcs/', AutomaticTableConstructionList.as_view(), name="atcs"),
    path('atcs/<int:pk>/', AutomaticTableConstructionDetail.as_view(), name="atc"),
    path('configurations/', ConfigurationList.as_view(), name="configurations"),
    path('configurations/<int:pk>/', ConfigurationDetail.as_view(), name="configuration"),
    path('configuration_packs/', ConfigurationPackList.as_view(), name="configuration_packs"),
    path('configuration_packs/<int:pk>/', ConfigurationPackDetail.as_view(), name="configuration_pack"),
    path('enrollments/', EnrollmentList.as_view(), name="enrollments"),
    path('enrollments/<int:pk>/', EnrollmentDetail.as_view(), name="enrollment"),
    path('enrollments/<int:pk>/package/', EnrollmentPackage.as_view(),
         name="enrollment_package"),
    path('enrollments/<int:pk>/script/', EnrollmentScript.as_view(),
         name="enrollment_script"),
    path('enrollments/<int:pk>/powershell_script/', EnrollmentPowershellScript.as_view(),
         name="enrollment_powershell_script"),
    path('file_categories/', FileCategoryList.as_view(), name="file_categories"),
    path('file_categories/<int:pk>/', FileCategoryDetail.as_view(), name="file_category"),
    path('packs/<slug:slug>/', PackView.as_view(), name="pack"),
    path('queries/', QueryList.as_view(), name="queries"),
    path('queries/<int:pk>/', QueryDetail.as_view(), name="query"),
    path('runs/<int:pk>/results/export/',
         ExportDistributedQueryResults.as_view(), name="export_distributed_query_results"),
]
