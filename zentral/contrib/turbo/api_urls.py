from django.urls import path
from .api_views import (ConfigurationList, ConfigurationDetail,
                        EnrollmentList, EnrollmentDetail,
                        EnrollmentPlist, EnrollmentConfigurationProfile,
                        MSCPCheckList, MSCPCheckDetail,
                        OneTimeJobList, OneTimeJobDetail,
                        RecurringJobList, RecurringJobDetail,
                        ScriptList, ScriptDetail)


app_name = "turbo_api"
urlpatterns = [
    path('configurations/', ConfigurationList.as_view(), name="configurations"),
    path('configurations/<uuid:pk>/', ConfigurationDetail.as_view(), name="configuration"),
    path('enrollments/', EnrollmentList.as_view(), name="enrollments"),
    path('enrollments/<int:pk>/', EnrollmentDetail.as_view(), name="enrollment"),
    path('enrollments/<int:pk>/plist/', EnrollmentPlist.as_view(), name="enrollment_plist"),
    path('enrollments/<int:pk>/configuration_profile/', EnrollmentConfigurationProfile.as_view(),
         name="enrollment_configuration_profile"),
    path('scripts/', ScriptList.as_view(), name="scripts"),
    path('scripts/<uuid:pk>/', ScriptDetail.as_view(), name="script"),
    path('mscp_checks/', MSCPCheckList.as_view(), name="mscp_checks"),
    path('mscp_checks/<uuid:pk>/', MSCPCheckDetail.as_view(), name="mscp_check"),
    path('recurring_jobs/', RecurringJobList.as_view(), name="recurring_jobs"),
    path('recurring_jobs/<uuid:pk>/', RecurringJobDetail.as_view(), name="recurring_job"),
    path('one_time_jobs/', OneTimeJobList.as_view(), name="one_time_jobs"),
    path('one_time_jobs/<uuid:pk>/', OneTimeJobDetail.as_view(), name="one_time_job"),
]
