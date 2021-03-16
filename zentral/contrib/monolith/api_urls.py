from django.urls import path
from .api_views import SyncRepository, UpdateCacheServer


app_name = "monolith_api"
urlpatterns = [
    path('repository/sync/', SyncRepository.as_view(), name="sync_repository"),
    path('manifests/<int:pk>/cache_servers/', UpdateCacheServer.as_view(), name="update_cache_server"),
]
