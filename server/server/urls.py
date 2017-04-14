from django.conf.urls import include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from zentral.conf import saml2_idp_metadata_file, settings as zentral_settings

# base
urlpatterns = [
    url(r'^', include('base.urls', namespace='base')),
    url(r'^admin/users/', include('accounts.urls', namespace='users')),
    url(r'^accounts/', include('django.contrib.auth.urls')),
]

# zentral apps
for app_name in zentral_settings.get('apps', []):
    app_shortname = app_name.rsplit('.', 1)[-1]
    url_module = "{}.urls".format(app_name)
    try:
        urlpatterns.append(url(r'^{}/'.format(app_shortname), include(url_module, namespace=app_shortname)))
    except ImportError:
        # TODO use ModuleNotFoundError for python >= 3.6
        pass

# saml2
if saml2_idp_metadata_file:
    urlpatterns.append(url(r'^saml2/', include('accounts.saml2_urls', namespace='saml2')))

# static files
urlpatterns += staticfiles_urlpatterns()
