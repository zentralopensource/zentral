from django.conf.urls import url
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # Sync
    url(r'^webhook/$', views.WebHookView.as_view(), name='webhook'),

    # Pkg infos
    url(r'^pkg_infos/$', views.PkgInfosView.as_view(), name='pkg_infos'),
    url(r'^pkg_infos/(?P<pk>\d+)/update_catalog/$',
        views.UpdatePkgInfoCatalogView.as_view(),
        name='update_pkg_info_catalog'),
    url(r'^pkg_info_names/(?P<pk>\d+)/$', views.PkgInfoNameView.as_view(), name='pkg_info_name'),

    # Printer ppd
    url(r'^ppds/$', views.PPDsView.as_view(), name='ppds'),
    url(r'^ppds/upload/$', views.UploadPPDView.as_view(), name='upload_ppd'),
    url(r'^ppds/(?P<pk>\d+)/$', views.PPDView.as_view(), name='ppd'),

    # Catalogs
    url(r'^catalogs/$', views.CatalogsView.as_view(), name='catalogs'),
    url(r'^catalogs/create/$', views.CreateCatalogView.as_view(), name='create_catalog'),
    url(r'^catalogs/(?P<pk>\d+)/$', views.CatalogView.as_view(), name='catalog'),
    url(r'^catalogs/(?P<pk>\d+)/update/$', views.UpdateCatalogView.as_view(), name='update_catalog'),
    url(r'^catalogs/(?P<pk>\d+)/update_priority/$',
        views.UpdateCatalogPriorityView.as_view(),
        name='update_catalog_priority'),
    url(r'^catalogs/(?P<pk>\d+)/delete/$', views.DeleteCatalogView.as_view(), name='delete_catalog'),

    # Sub manifests
    url(r'^sub_manifests/$', views.SubManifestsView.as_view(), name='sub_manifests'),
    url(r'^sub_manifests/create/$', views.CreateSubManifestView.as_view(), name='create_sub_manifest'),
    url(r'^sub_manifests/(?P<pk>\d+)/$', views.SubManifestView.as_view(), name='sub_manifest'),
    url(r'^sub_manifests/(?P<pk>\d+)/update/$', views.UpdateSubManifestView.as_view(), name='update_sub_manifest'),
    url(r'^sub_manifests/(?P<pk>\d+)/delete/$', views.DeleteSubManifestView.as_view(), name='delete_sub_manifest'),
    url(r'^sub_manifests/(?P<pk>\d+)/add_pkg_info/$',
        views.SubManifestAddPkgInfoView.as_view(), name='sub_manifest_add_pkg_info'),
    url(r'^sub_manifest_pkg_infos/(?P<pk>\d+)/delete/$',
        views.DeleteSubManifestPkgInfoView.as_view(), name='delete_sub_manifest_pkg_info'),
    url(r'^sub_manifests/(?P<pk>\d+)/add_attachment/$',
        views.SubManifestAddAttachmentView.as_view(), name='sub_manifest_add_attachment'),
    url(r'^sub_manifests/(?P<pk>\d+)/add_script/$',
        views.SubManifestAddScriptView.as_view(), name='sub_manifest_add_script'),
    url(r'^sub_manifests/(?P<sm_pk>\d+)/script/(?P<pk>\d+)/update/$',
        views.SubManifestUpdateScriptView.as_view(), name='sub_manifest_update_script'),
    url(r'^sub_manifests_attachment/(?P<pk>\d+)/delete/$',
        views.DeleteSubManifestAttachmentView.as_view(), name='delete_sub_manifest_attachment'),

    # Manifests
    url(r'^manifests/$', views.ManifestsView.as_view(), name='manifests'),
    url(r'^manifests/create/$', views.CreateManifestView.as_view(), name='create_manifest'),
    url(r'^manifests/(?P<pk>\d+)/$', views.ManifestView.as_view(), name='manifest'),
    url(r'^manifests/(?P<pk>\d+)/enrollment/$',
        views.ManifestEnrollmentView.as_view(), name="manifest_enrollment"),
    url(r'^manifests/(?P<pk>\d+)/enrollment_pkg/$',
        views.ManifestEnrollmentPkgView.as_view(), name='manifest_enrollment_pkg'),
    url(r'^manifests/(?P<pk>\d+)/add_catalog/$',
        views.AddManifestCatalogView.as_view(), name='add_manifest_catalog'),
    url(r'^manifests/(?P<pk>\d+)/delete_catalog/(?P<m2m_pk>\d+)/$',
        views.DeleteManifestCatalogView.as_view(), name='delete_manifest_catalog'),
    url(r'^manifests/(?P<pk>\d+)/add_enrollment_package/$',
        views.AddManifestEnrollmentPackageView.as_view(), name='add_manifest_enrollment_package'),
    url(r'^manifests/(?P<pk>\d+)/update_enrollment_package/(?P<mep_pk>\d+)/$',
        views.UpdateManifestEnrollmentPackageView.as_view(), name='update_manifest_enrollment_package'),
    url(r'^manifests/(?P<pk>\d+)/delete_enrollment_package/(?P<mep_pk>\d+)/$',
        views.DeleteManifestEnrollmentPackageView.as_view(), name='delete_manifest_enrollment_package'),
    # manifest printers
    url(r'^manifests/(?P<m_pk>\d+)/add_printer/$',
        views.AddManifestPrinterView.as_view(), name='add_manifest_printer'),
    url(r'^manifests/(?P<m_pk>\d+)/printers/(?P<pk>\d+)/update/$',
        views.UpdateManifestPrinterView.as_view(), name='update_manifest_printer'),
    url(r'^manifests/(?P<m_pk>\d+)/printers/(?P<pk>\d+)/delete/$',
        views.DeleteManifestPrinterView.as_view(), name='delete_manifest_printer'),
    # manifest sub manifests
    url(r'^manifests/(?P<pk>\d+)/add_sub_manifest/$',
        views.AddManifestSubManifestView.as_view(), name='add_manifest_sub_manifest'),
    url(r'^manifests/(?P<pk>\d+)/delete_sub_manifest/(?P<m2m_pk>\d+)/$',
        views.DeleteManifestSubManifestView.as_view(), name='delete_manifest_sub_manifest'),
    url(r'^manifests/(?P<pk>\d+)/configure_cache_server/$',
        views.ConfigureManifestCacheServerView.as_view(), name='configure_manifest_cache_server'),
    url(r'^manifests/(?P<pk>\d+)/delete_cache_server/(?P<cs_pk>\d+)/$',
        views.DeleteManifestCacheServerView.as_view(), name='delete_manifest_cache_server'),

    # API
    url(r'^sync_catalogs/$', csrf_exempt(views.SyncCatalogsView.as_view()),
        name='sync_catalogs'),
    url(r'^cache_servers/$', csrf_exempt(views.CacheServersView.as_view()),
        name='cache_servers'),
    url(r'^download_printer_ppd/(?P<token>.*)/$', views.DownloadPrinterPPDView.as_view(),
        name='download_printer_ppd'),


    # managedsoftwareupdate API
    url(r'^munki_repo/catalogs/(?P<name>.*)$', views.MRCatalogView.as_view()),
    url(r'^munki_repo/manifests/(?P<name>.*)$', views.MRManifestView.as_view()),
    url(r'^munki_repo/pkgs/(?P<name>.*)$', views.MRPackageView.as_view()),
    url(r'^munki_repo/icons/(?P<name>.*)$', views.MRRedirectView.as_view(section="icons")),
    url(r'^munki_repo/client_resources/(?P<name>.*)$', views.MRRedirectView.as_view(section="client_resources")),
]


main_menu_cfg = {
    'weight': 10,
    'items': (
        ('webhook', 'Webhook'),
        ('catalogs', 'Catalogs'),
        ('pkg_infos', 'PkgInfos'),
        ('ppds', 'Printer PPDs'),
        ('manifests', 'Manifests'),
        ('sub_manifests', 'Sub manifests'),
    )
}
