from functools import partial
from django.utils.crypto import get_random_string
from django.utils.functional import SimpleLazyObject


CSP_HEADER = 'Content-Security-Policy'


DEFAULT_CSP_POLICIES = {
  "default-src": "'self'",
  "script-src": "'self'",
  "base-uri": "'none'",
  "form-action": "'self'",
  "frame-ancestors": "'none'",
  "object-src": "'none'",
  "style-src": "'self' 'unsafe-inline'",
}


def make_csp_nonce(request, length=16):
    if not getattr(request, '_csp_nonce', None):
        request._csp_nonce = get_random_string(length)
    return request._csp_nonce


def build_csp_header(request):
    csp_policies = DEFAULT_CSP_POLICIES.copy()
    csp_nonce = getattr(request, '_csp_nonce', None)
    if csp_nonce:
        csp_policies["script-src"] += " 'nonce-{}'".format(csp_nonce)
    return ";".join("{} {}".format(k, v) for k, v in csp_policies.items())


def csp_middleware(get_response):
    def middleware(request):
        nonce_func = partial(make_csp_nonce, request)
        request.csp_nonce = SimpleLazyObject(nonce_func)

        response = get_response(request)

        if CSP_HEADER in response:
            return response

        response[CSP_HEADER] = build_csp_header(request)

        return response

    return middleware
