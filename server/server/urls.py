import logging
from django.urls import include, path
from django.contrib.auth import views as auth_views
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from accounts.views import login
from zentral.conf import settings as zentral_settings

logger = logging.getLogger(__name__)

# base
urlpatterns = [
    path('', include('base.urls')),
    path('api/', include('base.api_urls')),

    # user admin views
    path('accounts/', include('accounts.urls')),

    # special login view with verification device redirect
    path('accounts/login/', login, name='login'),

    # add all the auth urls except the login
    path('accounts/logout/', auth_views.LogoutView.as_view(),
         name='logout'),
    path('accounts/password_change/', auth_views.PasswordChangeView.as_view(),
         name='password_change'),
    path('accounts/password_change/done/', auth_views.PasswordChangeDoneView.as_view(),
         name='password_change_done'),
    path('accounts/password_reset/', auth_views.PasswordResetView.as_view(),
         name='password_reset'),
    path('accounts/password_reset/done/', auth_views.PasswordResetDoneView.as_view(),
         name='password_reset_done'),
    path('accounts/reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('accounts/reset/done/', auth_views.PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
]


# zentral apps
def build_urlpatterns_for_zentral_apps():
    """ Builds urlpatterns objects from zentral app configurations.

    Returns:
        urlpatterns: a list of path or re_path elements
    """
    urlpatterns = []
    for app_name, app_config in zentral_settings.get('apps', {}).items():
        app_shortname = app_name.rsplit('.', 1)[-1]
        for url_prefix, url_module_name in (("", "urls"),
                                            ("api/", "api_urls"),
                                            ("metrics/", "metrics_urls"),
                                            ("public/", "public_urls")):
            if url_module_name == "metrics_urls" and not app_config.get("metrics", False):
                continue
            try:
                urlpatterns.append(path(f"{url_prefix}{app_shortname}/", include(f"{app_name}.{url_module_name}")))
                if (url_module_name == "public_urls" and app_config.get('mount_legacy_public_endpoints', False)):
                    urlpatterns.append(
                        path(
                            f"{app_shortname}/",
                            include(
                                f"{app_name}.{url_module_name}",
                                namespace=f"{app_shortname}_public_legacy"
                            )
                        )
                    )
            except ModuleNotFoundError:
                pass
    return urlpatterns


urlpatterns.extend(build_urlpatterns_for_zentral_apps())

# static files
urlpatterns += staticfiles_urlpatterns()
