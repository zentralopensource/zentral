from django.urls import path
from . import public_views

urlpatterns = [
    path('<uuid:uuid>/saml/acs/', public_views.AssertionConsumerServiceView.as_view(), name="saml_acs"),
    path('<uuid:uuid>/saml/metadata/', public_views.MetadataView.as_view(), name="saml_metadata"),
]
