import json
import logging
import warnings
import zlib
from django import forms
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views.generic import TemplateView, View
from django.views.generic.edit import FormView
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaBusinessUnit, BusinessUnit
from zentral.core.exceptions import ImproperlyConfigured

logger = logging.getLogger('zentral.utils.api_views')


API_SECRET_MIN_LENGTH = 32


def get_api_secret(settings):
    err_msg = None
    try:
        secret = settings['api']['secret']
    except KeyError:
        err_msg = "Missing api.secret key in conf"
    else:
        if not isinstance(secret, str):
            err_msg = "api.secret must be a str"
        elif len(secret) < API_SECRET_MIN_LENGTH:
            warnings.warn("Your api.secret has less than {} characters.".format(API_SECRET_MIN_LENGTH))
    if err_msg:
        raise ImproperlyConfigured(err_msg)
    return secret


API_SECRET = get_api_secret(settings)


class APIAuthError(Exception):
    pass


def verify_secret(secret, module):
    data = {}
    if "$" in secret:
        #
        # There is no $ in the signed secret produced by the django signing module (base64 + :)
        # Try to verify a simple structure:
        #
        # secret = signed_secret$id_attribute$id_value
        #
        # Only used for now with id_attribute == SERIAL and id_value == machine serial number
        # Usefull to get the machine serial number when the signed_secret is shared
        # among a fleet of machines for easy deployment
        #
        try:
            secret, method, value = secret.split('$', 2)
        except ValueError:
            raise APIAuthError('Malformed secret')
        if method != 'SERIAL':
            raise APIAuthError('Invalid secret method')
        if not value:
            raise APIAuthError('Invalid secret value')
        data['machine_serial_number'] = value  # NOT VERIFIED
    try:
        data.update(signing.loads(secret, key=API_SECRET))
    except signing.BadSignature:
        raise APIAuthError('Bad secret signature')
    if data['module'] != module:
        raise APIAuthError('Invalid module')
    bu_k = data.pop('bu_k', None)
    if bu_k:
        # TODO: cache
        qs = BusinessUnit.objects.select_related('source')
        l = list(qs.filter(key__startswith=bu_k,
                           source__module='zentral.contrib.inventory').order_by('-id'))
        if not l:
            logger.error('Unknown BU %s', bu_k)
        else:
            if len(l) > 1:
                logger.error('Found multiple BU for key %s', bu_k)
            data['business_unit'] = l[0]
    return data


def make_secret(module, business_unit=None):
    data = {'module': module}
    if business_unit:
        data['bu_k'] = business_unit.get_short_key()
    return signing.dumps(data, key=API_SECRET)


class JSONPostAPIView(View):
    payload_encoding = 'utf-8'

    def check_request_secret(self, request, *args, **kwargs):
        # ALWAYS PASS !
        pass

    def dispatch(self, request, *args, **kwargs):
        try:
            self.check_request_secret(request, *args, **kwargs)
        except APIAuthError as auth_err:
            return HttpResponseForbidden(str(auth_err))
        self.user_agent = request.META.get("HTTP_USER_AGENT", "")
        self.ip = request.META.get("HTTP_X_REAL_IP", "")
        return super().dispatch(request, *args, **kwargs)

    def check_data_secret(self, data):
        # ALWAYS PASS !
        pass

    def do_post(self, data):
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        payload = request.body
        if not payload:
            data = payload
        else:
            if request.META.get('HTTP_CONTENT_ENCODING', None) in ['zlib', 'gzip']:
                payload = zlib.decompress(payload)
            try:
                payload = payload.decode(self.payload_encoding)
            except UnicodeDecodeError:
                err_msg_tmpl = 'Could not decode payload with encoding %s'
                logger.error(err_msg_tmpl, self.payload_encoding, extra={'request': request})
                raise SuspiciousOperation(err_msg_tmpl % self.payload_encoding)
            try:
                data = json.loads(payload)
            except ValueError:
                raise SuspiciousOperation("Payload is not valid json")
        try:
            self.check_data_secret(data)
        except APIAuthError as auth_err:
            logger.error("APIAuthError %s", auth_err, extra={'request': request})
            return HttpResponseForbidden(str(auth_err))
        response_data = self.do_post(data)
        return JsonResponse(response_data)


class SignedRequestJSONPostAPIView(JSONPostAPIView):
    verify_module = None

    def get_request_secret(self, request, *args, **kwargs):
        raise NotImplementedError

    def check_request_secret(self, request, *args, **kwargs):
        req_sec = self.get_request_secret(request, *args, **kwargs)
        if self.verify_module is None:
            raise ImproperlyConfigured("self.verify_module is null")
        data = verify_secret(req_sec, self.verify_module)
        self.machine_serial_number = data.get('machine_serial_number', None)
        self.business_unit = data.get('business_unit', None)


class SignedRequestHeaderJSONPostAPIView(SignedRequestJSONPostAPIView):
    api_secret_header = "Zentral-API-Secret"
    api_secret_header_key = "HTTP_ZENTRAL_API_SECRET"

    def get_request_secret(self, request, *args, **kwargs):
        req_sec = request.META.get(self.api_secret_header_key, None)
        auth_err = None
        if req_sec is None:
            auth_err = "Missing {} header".format(self.api_secret_header)
        elif not req_sec:
            auth_err = "Empty {} header".format(self.api_secret_header)
        if auth_err:
            raise APIAuthError(auth_err)
        return req_sec

# Enrollment


class EnrollmentForm(forms.Form):
    meta_business_unit = forms.ModelChoiceField(
        label=_("Business unit"),
        queryset=MetaBusinessUnit.objects.available_for_api_enrollment(),
        required=False,
    )

    def get_build_kwargs(self):
        return {}


class BaseEnrollmentView(TemplateView):
    form_class = EnrollmentForm

    def get_context_data(self, **kwargs):
        context = super(BaseEnrollmentView, self).get_context_data(**kwargs)
        context['setup'] = True
        context['form'] = self.form_class()
        return context


class BaseInstallerPackageView(FormView):
    form_class = EnrollmentForm

    def form_valid(self, form):
        try:
            tls_server_certs = settings['api']['tls_server_certs']
        except KeyError:
            tls_server_certs = None
        builder = self.builder()
        business_unit = None
        meta_business_unit = form.cleaned_data['meta_business_unit']
        if meta_business_unit:
            # TODO Race. The meta_business_unit could maybe be without any api BU.
            # TODO. Better selection if multiple BU ?
            business_unit = meta_business_unit.api_enrollment_business_units()[0]
        build_kwargs = form.get_build_kwargs()
        return builder.build_and_make_response(business_unit,
                                               self.request.get_host(),
                                               make_secret(self.module, business_unit),
                                               tls_server_certs,
                                               **build_kwargs)
