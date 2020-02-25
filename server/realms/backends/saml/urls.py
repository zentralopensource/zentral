from django.urls import path
from . import views

urlpatterns = [
    path('<uuid:uuid>/saml/acs/', views.AssertionConsumerServiceView.as_view(), name="saml_acs"),
    path('<uuid:uuid>/saml/metadata/', views.MetadataView.as_view(), name="saml_metadata"),
]
