from django.urls import path
from . import public_views

urlpatterns = [
    path('<uuid:uuid>/openidc/ac_redirect/',
         public_views.AuthorizationCodeFlowRedirectView.as_view(),
         name="openidc_ac_redirect"),
]
