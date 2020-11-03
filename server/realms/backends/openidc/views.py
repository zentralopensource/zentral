from datetime import datetime
import logging
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import View
from realms.exceptions import RealmUserError
from realms.models import Realm, RealmAuthenticationSession
from realms.views import ras_finalization_error


logger = logging.getLogger("zentral.realms.backends.openidc.views")


class AuthorizationCodeFlowRedirectView(View):
    def get(self, request, *args, **kwargs):
        # realm
        uuid = kwargs.pop("uuid")
        realm = get_object_or_404(Realm, uuid=uuid, backend="openidc")
        backend_instance = realm.backend_instance

        # find realm auth session
        state = request.GET.get("state")
        if not state:
            raise SuspiciousOperation("Missing state")

        # verify that state is in the session
        if not backend_instance.verify_session_state(request, state):
            raise SuspiciousOperation("CSRF verification failed")

        try:
            ras = RealmAuthenticationSession.objects.select_for_update().get(realm=realm, pk=state)
        except RealmAuthenticationSession.DoesNotExist:
            raise SuspiciousOperation("Unknown state")

        if ras.user:
            raise SuspiciousOperation("Realm authorization session already used")

        # authorization code
        code = request.GET.get("code")
        if not code:
            raise SuspiciousOperation("Missing code")

        # exchange code for tokens, and build realm user with them
        code_verifier = None
        if ras.backend_state:
            code_verifier = ras.backend_state.get("code_verifier")

        try:
            realm_user = backend_instance.update_or_create_realm_user(code, code_verifier)
        except RealmUserError as e:
            logger.exception("Could not update or create realm user")
            return ras_finalization_error(request, ras, exception=e)

        # use the 'exp' claim as default session expiry
        try:
            expires_at = datetime.fromtimestamp(realm_user.claims["exp"])
        except (KeyError, TypeError, ValueError):
            expires_at = None

        # finalize the authentication session
        redirect_url = None
        try:
            redirect_url = ras.finalize(request, realm_user, expires_at)
        except Exception as e:
            logger.exception("Could not finalize the authentication session")
            return ras_finalization_error(request, ras, realm_user=realm_user, exception=e)
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty authentication session redirect url")
