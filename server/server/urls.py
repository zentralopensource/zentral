import logging
from django.conf.urls import include, url
from django.contrib.auth.urls import urlpatterns as auth_urlpatterns
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from accounts.views import login, VerifyTOTPView, VerifyU2FView
from zentral.conf import settings as zentral_settings

logger = logging.getLogger(__name__)

# base
urlpatterns = [
    url(r'^', include('base.urls')),
    url(r'^api/', include('base.api_urls')),
    url(r'^admin/users/', include('accounts.urls')),
    url(r'^realms/', include('realms.urls')),
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
    for url_prefix, url_module_name in (("", "urls"),
                                        ("api/", "api_urls")):
        url_module = "{}.{}".format(app_name, url_module_name)
        try:
            urlpatterns.append(url(r'^{p}{a}/'.format(p=url_prefix, a=app_shortname), include(url_module)))
        except ImportError as error:
            if error.__class__.__name__ == "ModuleNotFoundError" or "NO MODULE" in str(error).upper():
                pass
            else:
                logger.exception("Could not load app %s %s", app_shortname, url_module_name)

# static files
urlpatterns += staticfiles_urlpatterns()
