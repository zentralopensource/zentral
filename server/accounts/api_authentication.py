from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from .models import APIToken
from zentral.utils.token import verify_ztl_token, USER_API_TOKEN, SERVICE_ACCOUNT_API_TOKEN


class APITokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        # TODO: remove _ check in 2026.4
        if '_' in key and not verify_ztl_token(key, [USER_API_TOKEN, SERVICE_ACCOUNT_API_TOKEN]):
            raise exceptions.AuthenticationFailed(_('Invalid ztl token.'))
        try:
            token = APIToken.objects.get_with_key(key)
        except APIToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)
