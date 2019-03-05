from xml.etree import ElementTree
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.core.signing import BadSignature, Signer
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.utils.http import is_safe_url
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from saml2 import BINDING_HTTP_POST, md, saml, samlp, xmlenc, xmldsig
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.metadata import entity_descriptor
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from zentral.conf import saml2_idp_metadata_file


# adapted from https://github.com/jpf/okta-pysaml2-example/blob/master/app.py


class BaseSPView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        self.signer = Signer()
        return super().dispatch(request, *args, **kwargs)

    @cached_property
    def idp_metadata(self):
        with open(saml2_idp_metadata_file, "r") as f:
            return f.read()

    def get_saml2_config(self, request):
        acs_url = request.build_absolute_uri(reverse("saml2:acs"))
        entity_id = request.build_absolute_uri(reverse("saml2:metadata"))
        settings = {
            "metadata": {
                "inline": [self.idp_metadata],
            },
            "entityid": entity_id,
            "service": {
                "sp": {
                    "name_id_format": NAMEID_FORMAT_EMAILADDRESS,
                    "endpoints": {
                        "assertion_consumer_service": [
                            (acs_url, BINDING_HTTP_POST),
                        ],
                    },
                    "allow_unsolicited": True,
                    "authn_requests_signed": False,
                    "logout_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": False,
                },
            },
        }
        sp_config = Saml2Config()
        sp_config.allow_unknown_attributes = True
        sp_config.load(settings)
        return sp_config

    def get_saml2_client(self, request):
        saml2_client = Saml2Client(config=self.get_saml2_config(request))
        return saml2_client


class AssertionConsumerServiceView(BaseSPView):
    def post(self, request, *args, **kwargs):
        saml2_client = self.get_saml2_client(request)
        authn_response = saml2_client.parse_authn_request_response(request.POST['SAMLResponse'], BINDING_HTTP_POST)
        session_info = authn_response.session_info()
        user = authenticate(request=request, session_info=session_info)
        if not user:
            raise ValueError("NO SAML2 USER")
        else:
            request.session.set_expiry(0)
            login(request, user)
        # redirect
        redirect = settings.LOGIN_REDIRECT_URL
        relay_state = request.POST.get("RelayState")
        if relay_state:
            try:
                redirect = self.signer.unsign(relay_state)
            except BadSignature:
                pass
        return HttpResponseRedirect(redirect)


class SSORedirectView(BaseSPView):
    def get(self, request, *args, **kwargs):
        saml2_client = self.get_saml2_client(request)
        relay_state = ""
        next_url = request.GET.get("next")
        if next_url and is_safe_url(url=next_url,
                                    allowed_hosts={self.request.get_host()},
                                    require_https=self.request.is_secure()):
            relay_state = self.signer.sign(next_url)
        request_id, request_info = saml2_client.prepare_for_authenticate(relay_state=relay_state)
        redirect_url = dict(request_info["headers"])["Location"]
        response = HttpResponseRedirect(redirect_url)
        response['Pragma'] = 'no-cache'
        response['Cache-Control'] = 'no-cache, no-store'
        return response


class MetadataView(BaseSPView):
    def get(self, request, *args, **kwargs):
        saml2_config = self.get_saml2_config(request)
        metadata = entity_descriptor(saml2_config)
        return HttpResponse(str(metadata).encode("utf-8"),
                            content_type="text/xml; charset=utf8")


# adapted from https://github.com/knaperek/djangosaml2/blob/master/djangosaml2/views.py


def register_namespace_prefixes():
    prefixes = (('saml', saml.NAMESPACE),
                ('samlp', samlp.NAMESPACE),
                ('md', md.NAMESPACE),
                ('ds', xmldsig.NAMESPACE),
                ('xenc', xmlenc.NAMESPACE))
    for prefix, namespace in prefixes:
        ElementTree.register_namespace(prefix, namespace)


register_namespace_prefixes()
