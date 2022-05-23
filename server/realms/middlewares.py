from django.utils.functional import SimpleLazyObject


SESSION_KEY = "realm_authentication_session"


def get_session(request):
    """
    Return the realm authentication session associated with the given request session.
    If no realm authentication session is retrieved, return an instance of `LocalAuthenticationSession`.
    """
    from .models import LocalAuthenticationSession, RealmAuthenticationSession
    ras = None
    try:
        ras_pk = request.session[SESSION_KEY]
    except KeyError:
        pass
    else:
        try:
            ras = RealmAuthenticationSession.objects.select_related("realm", "user").get(pk=ras_pk)
        except RealmAuthenticationSession.DoesNotExist:
            pass
    return ras or LocalAuthenticationSession()


def get_cached_session(request):
    if not hasattr(request, "_cached_ras"):
        request._cached_ras = get_session(request)
    return request._cached_ras


def realm_session_middleware(get_response):
    """monkey patch the user with information about the optional realm session"""

    def middleware(request):
        assert hasattr(request, 'session'), "This middleware requires session middleware to be installed."
        request.realm_authentication_session = SimpleLazyObject(lambda: get_cached_session(request))
        return get_response(request)

    return middleware
