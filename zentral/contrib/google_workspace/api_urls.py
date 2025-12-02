from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from zentral.contrib.google_workspace.api_views import (
    SyncTagsView, ConnectionList, ConnectionDetail, GroupTagMappingList, GroupTagMappingDetail)

app_name = "google_workspace_api"
urlpatterns = [
    path('connections/<uuid:conn_pk>/sync_tags/',
         SyncTagsView.as_view(), name="sync_tags"),
    path('connections/',
         ConnectionList.as_view(), name="connections"),
    path('connections/<uuid:pk>/',
         ConnectionDetail.as_view(), name="connection"),
    path('group_tag_mappings/',
         GroupTagMappingList.as_view(), name="group_tag_mappings"),
    path('group_tag_mappings/<uuid:pk>/',
         GroupTagMappingDetail.as_view(), name="group_tag_mapping"),
]

urlpatterns = format_suffix_patterns(urlpatterns)
