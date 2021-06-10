import logging
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from realms.exceptions import RealmUserError
from realms.models import RealmUser


logger = logging.getLogger("zentral.realms.backends.views")


def finalize_session(session, request, realm_user, expires_at=None):
    if session.user:
        raise ValueError("Session already finalized")
    elif not isinstance(realm_user, RealmUser):
        raise ValueError("invalid realm user")
    session.user = realm_user
    session.expires_at = expires_at
    session.save()
    callback_function = session.get_callback_function()
    if callback_function:
        response = None
        try:
            response = callback_function(request=request,
                                         realm_authentication_session=session,
                                         **session.callback_kwargs)
        except Exception as e:
            logger.exception("Could not finalize the authentication session")
            return ras_finalization_error(request, session, realm_user=realm_user, exception=e)
        else:
            if isinstance(response, HttpResponse):
                return response
            elif isinstance(response, str):
                return HttpResponseRedirect(response)
            else:
                raise ValueError("Wrong callback response")


def ras_finalization_error(request, ras, realm_user=None, exception=None):
    ctx = {"realm": ras.realm,
           "message": str(exception)}
    if isinstance(exception, RealmUserError):
        claims = exception.claims
        if claims:
            ctx["original_claims"] = claims.pop("claims", {})
            ctx["claims"] = claims
    if realm_user:
        ctx["original_claims"] = realm_user.claims
        ctx["claims"] = {
            k: v
            for k, v in ((a, getattr(realm_user, a))
                         for a in ("username", "email", "first_name", "last_name", "full_name"))
            if v
        }
    return render(request, "realms/ras_finalization_error.html", ctx, status=503)
