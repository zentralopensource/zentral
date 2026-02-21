from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from . import api_views

app_name = "accounts_api"
urlpatterns = [
    # oidc token issuer
    path(
        route="token_issuers/oidc/",
        view=api_views.OIDCAPITokenIssuerViewList.as_view(),
        name="oidc_api_token_issuers",
    ),
    path(
        route="token_issuers/oidc/<uuid:pk>/",
        view=api_views.OIDCAPITokenIssuerViewDetail.as_view(),
        name="oidc_api_token_issuer",
    ),
    path(
        route='token_issuers/oidc/<uuid:issuer_id>/auth/',
        view=api_views.OIDCAPITokenIssuerAuth.as_view(),
        name="oidc_api_token_issuer_exchange")
]
urlpatterns = format_suffix_patterns(urlpatterns)
