from django.urls import path
from . import public_views

app_name = "monolith_public"
urlpatterns = [
    path('munki_repo/catalogs/<path:name>',
         public_views.MRCatalogView.as_view(), name='repository_catalog'),
    path('munki_repo/manifests/<path:name>',
         public_views.MRManifestView.as_view(), name='repository_manifest'),
    path('munki_repo/pkgs/<path:name>',
         public_views.MRPackageView.as_view(), name='repository_package'),
    path('munki_repo/icons/_icon_hashes.plist',
         public_views.MRIconHashesView.as_view(), name='repository_icon_hashes'),
    path('munki_repo/icons/<path:name>',
         public_views.MRPackageView.as_view(), name='repository_icon'),
    path('munki_repo/client_resources/<path:name>',
         public_views.MRClientResourceView.as_view(), name='repository_client_resource'),
]
