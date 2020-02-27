from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import View
from realms.models import Realm, RealmAuthenticationSession


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
        realm_user = backend_instance.update_or_create_realm_user(code, code_verifier)

        # finalize the authentication session
        redirect_url = None
        try:
            redirect_url = ras.finalize(request, realm_user)
        except Exception:
            raise ValueError("Could not finalize the authentication session")
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty authentication session redirect url")
