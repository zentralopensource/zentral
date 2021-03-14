default_app_config = "realms.apps.ZentralRealmsAppConfig"

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
