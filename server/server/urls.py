import logging
from django.conf.urls import include, url
from django.contrib.auth.urls import urlpatterns as auth_urlpatterns
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from accounts.views import login, VerifyTOTPView, VerifyU2FView
from zentral.conf import saml2_idp_metadata_file, settings as zentral_settings

logger = logging.getLogger(__name__)

# base
urlpatterns = [
    url(r'^', include('base.urls', namespace='base')),
    url(r'^admin/users/', include('accounts.urls', namespace='users')),
    # special login view with verification device redirect
    url(r'^accounts/login/$', login, name='login'),
    url(r'^accounts/verify_totp/$', VerifyTOTPView.as_view(), name='verify_totp'),
    url(r'^accounts/verify_u2f/$', VerifyU2FView.as_view(), name='verify_u2f'),
]

# add all the auth url patterns except the login
for up in auth_urlpatterns:
    if up.name != 'login':
        urlpatterns.append(up)

# zentral apps
for app_name in zentral_settings.get('apps', []):
    app_shortname = app_name.rsplit('.', 1)[-1]
    url_module = "{}.urls".format(app_name)
    try:
        urlpatterns.append(url(r'^{}/'.format(app_shortname), include(url_module, namespace=app_shortname)))
    except ImportError as error:
        logger.exception("Could not load app urls %s", app_shortname)
        # TODO use ModuleNotFoundError for python >= 3.6
        pass

# saml2
if saml2_idp_metadata_file:
    urlpatterns.append(url(r'^saml2/', include('accounts.saml2_urls', namespace='saml2')))

# static files
urlpatterns += staticfiles_urlpatterns()
