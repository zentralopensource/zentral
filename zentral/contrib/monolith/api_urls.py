from django.urls import path
from .api_views import (SyncRepository, UpdateCacheServer,
                        CatalogList, CatalogDetail,
                        ManifestList, ManifestDetail)

app_name = "monolith_api"
urlpatterns = [
    path('repository/sync/', SyncRepository.as_view(), name="sync_repository"),
    path('catalogs/', CatalogList.as_view(), name="catalogs"),
    path('catalogs/<int:pk>/', CatalogDetail.as_view(), name="catalog"),
    path('manifests/', ManifestList.as_view(), name="manifests"),
    path('manifests/<int:pk>/', ManifestDetail.as_view(), name="manifest"),
    path('manifests/<int:pk>/cache_servers/', UpdateCacheServer.as_view(), name="update_cache_server"),
]
