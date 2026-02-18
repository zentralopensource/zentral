from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .api_views import OIDCAPITokenExchangeView

app_name = "accounts_api"
urlpatterns = [

    # oidc token issuer
    path(route='token_issuers/oicd/<uuid:issuer_id>/authenticate/',
         view=OIDCAPITokenExchangeView.as_view(),
         name="oidc_api_token_issuer_exchange")
]

urlpatterns = format_suffix_patterns(urlpatterns)
