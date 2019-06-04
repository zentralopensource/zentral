import base64
from gzip import GzipFile
import json
import logging
import warnings
import zlib
from asn1crypto import csr
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.generic import View
from zentral.conf import settings
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import BusinessUnit, MetaBusinessUnit
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.core.exceptions import ImproperlyConfigured
from .http import user_agent_and_ip_address_from_request

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
        data['machine_serial_number'] = value.strip().splitlines()[0]  # NOT VERIFIED
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
        bu_list = list(qs.filter(key__startswith=bu_k,
                                 source__module='zentral.contrib.inventory').order_by('-id'))
        if not bu_list:
            logger.error('Unknown BU %s', bu_k)
        else:
            if len(bu_list) > 1:
                logger.error('Found multiple BU for key %s', bu_k)
            data['business_unit'] = bu_list[0]
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
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
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
            content_encoding = request.META.get('HTTP_CONTENT_ENCODING', None)
            if content_encoding:
                # try to decompress the payload.
                if content_encoding == "deflate" \
                   or "santa" in self.user_agent and content_encoding == "zlib" \
                   or self.user_agent == "Zentral/mnkpf 0.1" and content_encoding == "gzip":
                    payload = zlib.decompress(payload)
                elif content_encoding == "gzip":
                    payload = GzipFile(fileobj=request).read()
                else:
                    return HttpResponse("Unsupported Media Type", status=415)
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


class BaseVerifySCEPCSRView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral"
    serial_number = None

    def post_event(self, scep_status, **event_payload):
        event_payload["scep_status"] = scep_status
        self.event_class.post_machine_request_payloads(self.serial_number, self.user_agent, self.ip,
                                                       [event_payload])

    def abort(self, reason, **event_payload):
        if reason:
            event_payload["reason"] = reason
        self.post_event("failure", **event_payload)
        raise SuspiciousOperation(reason)

    def do_post(self, data):
        csr_data = base64.b64decode(data["csr"].encode("ascii"))
        csr_info = csr.CertificationRequest.load(csr_data)["certification_request_info"]

        csr_d = {}

        # subject
        for rdn_idx, rdn in enumerate(csr_info["subject"].chosen):
            for type_val_idx, type_val in enumerate(rdn):
                csr_d[type_val["type"].native] = type_val['value'].native

        kwargs = {"user_agent": self.user_agent,
                  "public_ip_address": self.ip,
                  "serial_number": csr_d.pop("serial_number")}  # TODO: better system to find this attr in csr_d

        # meta business
        organization_name = csr_d.get("organization_name")
        if not organization_name or not organization_name.startswith("MBU$"):
            self.abort("Unknown organization name format")
        meta_business_unit_id = int(organization_name.split("$", 1)[-1])
        kwargs["meta_business_unit"] = get_object_or_404(MetaBusinessUnit, pk=meta_business_unit_id)

        # type and session secret
        try:
            cn_prefix, kwargs["secret"] = csr_d["common_name"].rsplit("$", 1)
        except (KeyError, ValueError, AttributeError):
            self.abort("Unknown common name format")

        model, status, update_status_method = self.get_enrollment_session_info(cn_prefix)
        kwargs["model"] = model
        kwargs["{}__status".format(model)] = status
        try:
            es_request = verify_enrollment_secret(**kwargs)
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            # update the enrollment session status
            enrollment_session = getattr(es_request.enrollment_secret, model)
            getattr(enrollment_session, update_status_method)(es_request)
            self.post_event("success", **enrollment_session.serialize_for_event())

        # OK
        return {"status": 0}
