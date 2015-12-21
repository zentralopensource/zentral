import json
import warnings
import zlib
from django.core import signing
from django.http import HttpResponseForbidden, JsonResponse
from django.views.generic import View
from zentral.conf import settings
from zentral.core.exceptions import ImproperlyConfigured


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
    return data


def make_secret(module):
    return signing.dumps({'module': module}, key=API_SECRET)


class JSONPostAPIView(View):
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
            payload = payload.decode('utf-8')
            data = json.loads(payload)
        try:
            self.check_data_secret(data)
        except APIAuthError as auth_err:
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
