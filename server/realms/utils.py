from django.conf import settings
from django.contrib.auth import authenticate, login


def login_callback(request, realm_user, next_url=None):
    """
    Realm authorization session callback used to log realm users in,
    as Zentral users
    """
    user = authenticate(request=request, realm_user=realm_user)
    if not user:
        raise ValueError("Could not authenticate realm user")
    else:
        request.session.set_expiry(0)
        login(request, user)
    return next_url or settings.LOGIN_REDIRECT_URL
