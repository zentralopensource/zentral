from django.urls import path
from .api_views import (SyncRepository, UpdateCacheServer,
                        CatalogList, CatalogDetail,
                        ConditionList, ConditionDetail,
                        ManifestList, ManifestDetail,
                        ManifestCatalogList, ManifestCatalogDetail,
                        ManifestSubManifestList, ManifestSubManifestDetail,
                        SubManifestList, SubManifestDetail)

app_name = "monolith_api"
urlpatterns = [
    path('repository/sync/', SyncRepository.as_view(), name="sync_repository"),
    path('catalogs/', CatalogList.as_view(), name="catalogs"),
    path('catalogs/<int:pk>/', CatalogDetail.as_view(), name="catalog"),
    path('conditions/', ConditionList.as_view(), name="conditions"),
    path('conditions/<int:pk>/', ConditionDetail.as_view(), name="condition"),
    path('manifests/', ManifestList.as_view(), name="manifests"),
    path('manifests/<int:pk>/', ManifestDetail.as_view(), name="manifest"),
    path('manifests/<int:pk>/cache_servers/', UpdateCacheServer.as_view(), name="update_cache_server"),
    path('manifest_catalogs/', ManifestCatalogList.as_view(), name="manifest_catalogs"),
    path('manifest_catalogs/<int:pk>/', ManifestCatalogDetail.as_view(), name="manifest_catalog"),
    path('manifest_sub_manifests/', ManifestSubManifestList.as_view(), name="manifest_sub_manifests"),
    path('manifest_sub_manifests/<int:pk>/', ManifestSubManifestDetail.as_view(), name="manifest_sub_manifest"),
    path('sub_manifests/', SubManifestList.as_view(), name="sub_manifests"),
    path('sub_manifests/<int:pk>/', SubManifestDetail.as_view(), name="sub_manifest"),
]
