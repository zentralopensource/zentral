import realms
from django.utils.functional import SimpleLazyObject


def get_session(request):
    if not hasattr(request, "_cached_ras"):
        request._cached_ras = realms.get_session(request)
    return request._cached_ras


def realm_session_middleware(get_response):
    """monkey patch the user with information about the optional realm session"""

    def middleware(request):
        assert hasattr(request, 'session'), "This middleware requires session middleware to be installed."
        request.realm_authentication_session = SimpleLazyObject(lambda: get_session(request))
        return get_response(request)

    return middleware
