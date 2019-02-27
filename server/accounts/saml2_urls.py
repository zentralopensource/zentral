from django.conf.urls import url

from . import saml2_views

app_name = "saml2"
urlpatterns = [
    url(r'^acs/$', saml2_views.AssertionConsumerServiceView.as_view(), name="acs"),
    url(r'^login/$', saml2_views.SSORedirectView.as_view(), name="login"),
    url(r'^metadata/$', saml2_views.MetadataView.as_view(), name="metadata"),
]
