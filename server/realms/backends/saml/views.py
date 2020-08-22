import logging
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from saml2 import BINDING_HTTP_POST
from saml2.metadata import entity_descriptor
from saml2.sigver import SignatureError
from realms.exceptions import RealmUserError
from realms.models import Realm, RealmAuthenticationSession
from realms.views import ras_finalization_error


# adapted from https://github.com/jpf/okta-pysaml2-example/blob/master/app.py


logger = logging.getLogger("zentral.realms.backends.saml.views")


class BaseSPView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        uuid = kwargs.pop("uuid")
        self.realm = get_object_or_404(Realm, uuid=uuid, backend="saml")
        self.backend_instance = self.realm.backend_instance
        return super().dispatch(request, *args, **kwargs)


class AssertionConsumerServiceView(BaseSPView):
    def post(self, request, *args, **kwargs):
        saml2_client = self.backend_instance.get_saml2_client()
        try:
            authn_response = saml2_client.parse_authn_request_response(request.POST['SAMLResponse'], BINDING_HTTP_POST)
        except SignatureError:
            raise SuspiciousOperation("Bad SAML signature")
        session_info = authn_response.session_info()
        # get the InResponseTo data
        in_response_to = None
        for assertion in authn_response.assertions:
            for subject_confirmation in assertion.subject.subject_confirmation:
                in_response_to = subject_confirmation.subject_confirmation_data.in_response_to
                break

        # find realm auth session
        relay_state = request.POST.get("RelayState")
        if not relay_state:
            raise SuspiciousOperation("Missing relay state")

        ras = None
        if relay_state != self.backend_instance.default_relay_state:
            if not in_response_to:
                raise SuspiciousOperation("Missing InResponseTo")
            try:
                ras = RealmAuthenticationSession.objects.select_for_update().get(realm=self.realm, pk=relay_state)
            except RealmAuthenticationSession.DoesNotExist:
                raise SuspiciousOperation("Unknown relay state")
            if ras.user:
                raise SuspiciousOperation("Realm authorization session already used")
            request_id = None
            if ras.backend_state:
                request_id = ras.backend_state.get("request_id")
            if not request_id:
                raise SuspiciousOperation("Missing request ID in auth session")
            if request_id != in_response_to:
                logger.error("SAML request ID %s != InResponseTo %s", request_id, in_response_to)
                raise SuspiciousOperation("Unsolicited response")
            else:
                logger.debug("SAML request ID = InResponseTo = {}".format(request_id))
            logger.info("Allow SAML response on realm '{}' {}".format(
                self.realm, self.realm.pk
            ))
        else:
            if self.backend_instance.allow_idp_initiated_login:
                logger.info("Allow unsolicited SAML response on realm '{}' {} for login".format(
                    self.realm, self.realm.pk
                ))
                # IdP-initiated login
                # create an on the fly auth session
                ras = RealmAuthenticationSession.objects.create(
                    realm=self.realm,
                    callback="realms.utils.login_callback"
                )
            else:
                logger.info("Unsolicited SAML response on realm '{}' {} redirected to SP initiated login".format(
                    self.realm, self.realm.pk
                ))
                # redirect to SP-initiated login
                redirect_url = "{}?realm={}".format(reverse("login"), self.realm.pk)
                return HttpResponseRedirect(redirect_url)

        try:
            realm_user = self.backend_instance.update_or_create_realm_user(session_info)
        except RealmUserError as e:
            logger.exception("Could not update or create realm user")
            return ras_finalization_error(request, ras, exception=e)

        # finalize the authentication session
        redirect_url = None
        try:
            redirect_url = ras.finalize(request, realm_user)
        except Exception as e:
            return ras_finalization_error(request, ras, realm_user=realm_user, exception=e)
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty authentication session redirect url")


class MetadataView(BaseSPView):
    def get(self, request, *args, **kwargs):
        saml2_config = self.backend_instance.get_saml2_config()
        metadata = entity_descriptor(saml2_config)
        return HttpResponse(str(metadata).encode("utf-8"),
                            content_type="text/xml; charset=utf8")
