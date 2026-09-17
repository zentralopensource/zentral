from django.urls import path
from .api_views import (EnrolledMachineList, ForceEnrolledMachineCleanSync, IngestFileInfo,
                        RuleList, RuleSetUpdate, TargetsExport, ConfigurationList,
                        ConfigurationDetail, EnrollmentList, EnrollmentDetail,
                        EnrollmentPlist, EnrollmentConfigurationProfile, RuleDetail,
                        ScopedClientModeList, ScopedClientModeDetail,
                        ScopedPathRegexList, ScopedPathRegexDetail)


app_name = "santa_api"
urlpatterns = [
    path('configurations/', ConfigurationList.as_view(), name="configurations"),
    path('configurations/<int:pk>/', ConfigurationDetail.as_view(), name="configuration"),
    path('enrolled_machines/', EnrolledMachineList.as_view(), name="enrolled_machines"),
    path('enrolled_machines/<int:pk>/force_clean_sync/', ForceEnrolledMachineCleanSync.as_view(),
         name="force_enrolled_machine_clean_sync"),
    path('enrollments/', EnrollmentList.as_view(), name="enrollments"),
    path('enrollments/<int:pk>/', EnrollmentDetail.as_view(), name="enrollment"),
    path('enrollments/<int:pk>/plist/', EnrollmentPlist.as_view(), name="enrollment_plist"),
    path('enrollments/<int:pk>/configuration_profile/', EnrollmentConfigurationProfile.as_view(),
         name="enrollment_configuration_profile"),
    path('ingest/fileinfo/', IngestFileInfo.as_view(), name="ingest_file_info"),
    path('rules/', RuleList.as_view(), name="rules"),
    path('rules/<int:pk>/', RuleDetail.as_view(), name="rule"),
    path('rulesets/update/', RuleSetUpdate.as_view(), name="ruleset_update"),
    path('scoped_client_modes/', ScopedClientModeList.as_view(), name="scoped_client_modes"),
    path('scoped_client_modes/<int:pk>/', ScopedClientModeDetail.as_view(), name="scoped_client_mode"),
    path('scoped_path_regexes/', ScopedPathRegexList.as_view(), name="scoped_path_regexes"),
    path('scoped_path_regexes/<int:pk>/', ScopedPathRegexDetail.as_view(), name="scoped_path_regex"),
    path('targets/export/', TargetsExport.as_view(), name="targets_export"),
]
