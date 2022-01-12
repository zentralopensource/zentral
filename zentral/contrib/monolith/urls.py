from django.urls import path
from . import views

app_name = "monolith"
urlpatterns = [
    # pkg infos
    path('pkg_infos/', views.PkgInfosView.as_view(), name='pkg_infos'),
    path('pkg_infos/<int:pk>/update_catalog/',
         views.UpdatePkgInfoCatalogView.as_view(),
         name='update_pkg_info_catalog'),
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

    # PPDs
    path('ppds/', views.PPDsView.as_view(), name='ppds'),
    path('ppds/upload/', views.UploadPPDView.as_view(), name='upload_ppd'),
    path('ppds/<int:pk>/', views.PPDView.as_view(), name='ppd'),

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
    path('sub_manifests/<int:pk>/add_attachment/',
         views.SubManifestAddAttachmentView.as_view(), name='sub_manifest_add_attachment'),
    path('sub_manifests/<int:pk>/add_script/',
         views.SubManifestAddScriptView.as_view(), name='sub_manifest_add_script'),
    path('sub_manifests/<int:sm_pk>/script/<int:pk>/update/',
         views.SubManifestUpdateScriptView.as_view(), name='sub_manifest_update_script'),
    path('sub_manifests_attachment/<int:pk>/delete/',
         views.DeleteSubManifestAttachmentView.as_view(), name='delete_sub_manifest_attachment'),
    path('sub_manifests_attachment/<int:pk>/purge/',
         views.PurgeSubManifestAttachmentView.as_view(), name='purge_sub_manifest_attachment'),
    path('sub_manifests_attachment/<int:pk>/download/',
         views.DownloadSubManifestAttachmentView.as_view(), name='download_sub_manifest_attachment'),

    # manifests
    path('manifests/', views.ManifestsView.as_view(), name='manifests'),
    path('manifests/create/', views.CreateManifestView.as_view(), name='create_manifest'),
    path('manifests/<int:pk>/', views.ManifestView.as_view(), name='manifest'),
    path('manifests/<int:pk>/update/', views.UpdateManifestView.as_view(), name='update_manifest'),
    path('manifests/<int:pk>/add_enrollment/',
         views.AddManifestEnrollmentView.as_view(),
         name="add_manifest_enrollment"),
    path('manifests/<int:manifest_pk>/enrollment/<int:pk>/configuration_plist/',
         views.ManifestEnrollmentConfigurationProfileView.as_view(format="plist"),
         name="manifest_enrollment_configuration_plist"),
    path('manifests/<int:manifest_pk>/enrollment/<int:pk>/configuration_profile/',
         views.ManifestEnrollmentConfigurationProfileView.as_view(format="configuration_profile"),
         name="manifest_enrollment_configuration_profile"),

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

    # manifest printers
    path('manifests/<int:m_pk>/add_printer/',
         views.AddManifestPrinterView.as_view(), name='add_manifest_printer'),
    path('manifests/<int:m_pk>/printers/<int:pk>/update/',
         views.UpdateManifestPrinterView.as_view(), name='update_manifest_printer'),
    path('manifests/<int:m_pk>/printers/<int:pk>/delete/',
         views.DeleteManifestPrinterView.as_view(), name='delete_manifest_printer'),

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

    # extra
    path('download_printer_ppd/<str:token>/', views.DownloadPrinterPPDView.as_view(),
         name='download_printer_ppd'),

    # managedsoftwareupdate API
    path('munki_repo/catalogs/<path:name>',
         views.MRCatalogView.as_view(), name='repository_catalog'),
    path('munki_repo/manifests/<path:name>',
         views.MRManifestView.as_view(), name='repository_manifest'),
    path('munki_repo/pkgs/<path:name>',
         views.MRPackageView.as_view(), name='repository_package'),
    path('munki_repo/icons/<path:name>',
         views.MRRedirectView.as_view(section="icons"), name='repository_icon'),
    path('munki_repo/client_resources/<path:name>',
         views.MRRedirectView.as_view(section="client_resources"), name='repository_client_resource'),
]


main_menu_cfg = {
    'weight': 10,
    'items': (
        ('catalogs', 'Catalogs', False, ("monolith.view_catalog",)),
        ('pkg_infos', 'PkgInfos', False, ("monolith.view_pkginfo",)),
        ('ppds', 'Printer PPDs', False, ("monolith.view_printerppd",)),
        ('conditions', 'Conditions', False, ("monolith.view_condition",)),
        ('manifests', 'Manifests', False, ("monolith.view_manifest",)),
        ('sub_manifests', 'Sub manifests', False, ("monolith.view_submanifest",)),
    )
}
