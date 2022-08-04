from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from .models import APIToken


class APITokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        try:
            token = APIToken.objects.get_with_key(key)
        except APIToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)
