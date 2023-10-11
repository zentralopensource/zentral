from django.urls import path
from . import views

app_name = "monolith"
urlpatterns = [
    # pkg infos
    path('pkg_infos/', views.PkgInfosView.as_view(), name='pkg_infos'),
    path('pkg_infos/<int:pk>/', views.PkgInfoNameView.as_view(), name='pkg_info'),
    path('pkg_infos/upload_package/', views.UploadPackageView.as_view(), name='upload_package'),
    path('pkg_infos/<int:pk>/update_package/', views.UpdatePackageView.as_view(), name='update_package'),
    path('pkg_infos/<int:pk>/update_catalog/',
         views.UpdatePkgInfoCatalogView.as_view(),
         name='update_pkg_info_catalog'),
    path('pkg_infos/<int:pk>/delete/', views.DeletePkgInfoView.as_view(), name='delete_pkg_info'),
    path('pkg_info_names/create/', views.CreatePkgInfoNameView.as_view(), name='create_pkg_info_name'),
    path('pkg_info_names/<int:pk>/', views.PkgInfoNameView.as_view(), name='pkg_info_name'),
    path('pkg_info_names/<int:pk>/events/',
         views.PkgInfoNameEventsView.as_view(),
         name='pkg_info_name_events'),
    path('pkg_info_names/<int:pk>/events/fetch/',
         views.FetchPkgInfoNameEventsView.as_view(),
         name='fetch_pkg_info_name_events'),
    path('pkg_info_names/<int:pk>/events/store_redirect/',
         views.PkgInfoNameEventsStoreRedirectView.as_view(),
         name='pkg_info_name_events_store_redirect'),
    path('pkg_info_names/<int:pk>/delete/', views.DeletePkgInfoNameView.as_view(), name='delete_pkg_info_name'),

    # catalogs
    path('catalogs/', views.CatalogsView.as_view(), name='catalogs'),
    path('catalogs/create/', views.CreateCatalogView.as_view(), name='create_catalog'),
    path('catalogs/<int:pk>/', views.CatalogView.as_view(), name='catalog'),
    path('catalogs/<int:pk>/update/', views.UpdateCatalogView.as_view(), name='update_catalog'),
    path('catalogs/<int:pk>/update_priority/',
         views.UpdateCatalogPriorityView.as_view(),
         name='update_catalog_priority'),
    path('catalogs/<int:pk>/delete/', views.DeleteCatalogView.as_view(), name='delete_catalog'),

    # conditions
    path('conditions/', views.ConditionsView.as_view(), name='conditions'),
    path('conditions/create/', views.CreateConditionView.as_view(), name='create_condition'),
    path('conditions/<int:pk>/', views.ConditionView.as_view(), name='condition'),
    path('conditions/<int:pk>/update/', views.UpdateConditionView.as_view(), name='update_condition'),
    path('conditions/<int:pk>/delete/', views.DeleteConditionView.as_view(), name='delete_condition'),

    # sub manifests
    path('sub_manifests/', views.SubManifestsView.as_view(), name='sub_manifests'),
    path('sub_manifests/create/', views.CreateSubManifestView.as_view(), name='create_sub_manifest'),
    path('sub_manifests/<int:pk>/', views.SubManifestView.as_view(), name='sub_manifest'),
    path('sub_manifests/<int:pk>/update/', views.UpdateSubManifestView.as_view(), name='update_sub_manifest'),
    path('sub_manifests/<int:pk>/delete/', views.DeleteSubManifestView.as_view(), name='delete_sub_manifest'),
    path('sub_manifests/<int:pk>/pkg_infos/add/',
         views.SubManifestAddPkgInfoView.as_view(), name='sub_manifest_add_pkg_info'),
    path('sub_manifests/<int:sm_pk>/pkg_infos/<int:pk>/update/',
         views.UpdateSubManifestPkgInfoView.as_view(), name='update_sub_manifest_pkg_info'),
    path('sub_manifests/<int:sm_pk>/pkg_infos/<int:pk>/delete/',
         views.DeleteSubManifestPkgInfoView.as_view(), name='delete_sub_manifest_pkg_info'),

    # manifests
    path('manifests/', views.ManifestsView.as_view(), name='manifests'),
    path('manifests/create/', views.CreateManifestView.as_view(), name='create_manifest'),
    path('manifests/<int:pk>/', views.ManifestView.as_view(), name='manifest'),
    path('manifests/<int:pk>/update/', views.UpdateManifestView.as_view(), name='update_manifest'),
    path('manifests/<int:pk>/add_enrollment/',
         views.AddManifestEnrollmentView.as_view(),
         name="add_manifest_enrollment"),

    # manifest machine info
    path('manifests/<int:pk>/machine_info/', views.ManifestMachineInfoView.as_view(), name='manifest_machine_info'),

    # manifest catalogs
    path('manifests/<int:pk>/catalogs/add/',
         views.AddManifestCatalogView.as_view(), name='add_manifest_catalog'),
    path('manifests/<int:pk>/catalogs/<int:m2m_pk>/edit/',
         views.EditManifestCatalogView.as_view(), name='edit_manifest_catalog'),
    path('manifests/<int:pk>/catalogs/<int:m2m_pk>/delete/',
         views.DeleteManifestCatalogView.as_view(), name='delete_manifest_catalog'),

    # manifest enrollment packages
    path('manifests/<int:pk>/add_enrollment_package/',
         views.AddManifestEnrollmentPackageView.as_view(), name='add_manifest_enrollment_package'),
    path('manifests/<int:pk>/update_enrollment_package/<int:mep_pk>/',
         views.UpdateManifestEnrollmentPackageView.as_view(), name='update_manifest_enrollment_package'),
    path('manifests/<int:pk>/delete_enrollment_package/<int:mep_pk>/',
         views.DeleteManifestEnrollmentPackageView.as_view(), name='delete_manifest_enrollment_package'),

    # manifest sub manifests
    path('manifests/<int:pk>/sub_manifests/add/',
         views.AddManifestSubManifestView.as_view(), name='add_manifest_sub_manifest'),
    path('manifests/<int:pk>/sub_manifests/<int:m2m_pk>/edit/',
         views.EditManifestSubManifestView.as_view(), name='edit_manifest_sub_manifest'),
    path('manifests/<int:pk>/sub_manifests/<int:m2m_pk>/delete/',
         views.DeleteManifestSubManifestView.as_view(), name='delete_manifest_sub_manifest'),

    # manifest cache servers
    path('manifests/<int:pk>/delete_cache_server/<int:cs_pk>/',
         views.DeleteManifestCacheServerView.as_view(), name='delete_manifest_cache_server'),

    # terraform
    path('terraform_export/',
         views.TerraformExportView.as_view(),
         name='terraform_export'),
]


modules_menu_cfg = {
    'items': (
        ('catalogs', 'Catalogs', False, ("monolith.view_catalog",)),
        ('pkg_infos', 'PkgInfos', False, ("monolith.view_pkginfo",)),
        ('conditions', 'Conditions', False, ("monolith.view_condition",)),
        ('manifests', 'Manifests', False, ("monolith.view_manifest",)),
        ('sub_manifests', 'Sub manifests', False, ("monolith.view_submanifest",)),
    )
}
