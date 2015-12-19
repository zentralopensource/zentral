from django.conf.urls import include, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from zentral.conf import settings as zentral_settings

# base
urlpatterns = [
    url(r'^', include('base.urls', namespace='base')),
]

# zentral apps
for app_name in zentral_settings.get('apps', []):
    app_shortname = app_name.rsplit('.', 1)[-1]
    url_module = "{}.urls".format(app_name)
    urlpatterns.append(url(r'^{}/'.format(app_shortname), include(url_module, namespace=app_shortname)))

# static files
urlpatterns += staticfiles_urlpatterns()
