from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import IngestFileInfo, RuleList, RuleSetUpdate, TargetsExport, ConfigurationList, ConfigurationDetail


app_name = "santa_api"
urlpatterns = [
    path('configurations/', ConfigurationList.as_view(), name="configurations"),
    path('configurations/<int:pk>/', ConfigurationDetail.as_view(), name="configuration"),
    path('ingest/fileinfo/', IngestFileInfo.as_view(), name="ingest_file_info"),
    path('rules/', RuleList.as_view(), name="rules"),
    path('rulesets/update/', RuleSetUpdate.as_view(), name="ruleset_update"),
    path('targets/export/', TargetsExport.as_view(), name="targets_export"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
