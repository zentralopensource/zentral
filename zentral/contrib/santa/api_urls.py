from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import IngestFileInfo, RuleSetUpdate


app_name = "santa_api"
urlpatterns = [
    url('^ingest/fileinfo/$', IngestFileInfo.as_view(), name="ingest_file_info"),
    url('^rulesets/update/$', RuleSetUpdate.as_view(), name="ruleset_update"),
]


urlpatterns = format_suffix_patterns(urlpatterns)
