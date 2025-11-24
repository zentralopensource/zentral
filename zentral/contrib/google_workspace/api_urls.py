from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from zentral.contrib.google_workspace.api_views import SyncTagsView

app_name = "google_workspace_api"
urlpatterns = [
    path('connections/<uuid:conn_pk>/sync_tags/',
         SyncTagsView.as_view(), name="sync_tags"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
