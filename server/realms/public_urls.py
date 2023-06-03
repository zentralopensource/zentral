from django.urls import path
from . import public_views
from realms.backends.ldap.public_urls import urlpatterns as ldap_urlpatterns
from realms.backends.saml.public_urls import urlpatterns as saml_urlpatterns
from realms.backends.openidc.public_urls import urlpatterns as openidc_urlpatterns


app_name = "realms_public"
urlpatterns = [
    # SSO login
    path('<uuid:pk>/login/', public_views.LoginView.as_view(), name='login'),
]
urlpatterns += ldap_urlpatterns
urlpatterns += saml_urlpatterns
urlpatterns += openidc_urlpatterns
