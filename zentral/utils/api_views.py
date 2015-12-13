import json
import zlib
from django.views.generic import View
from django.http import HttpResponseForbidden
from zentral.core.exceptions import ImproperlyConfigured

class CheckAPISecretView(View):
    api_secret_header = "Zentral-API-Secret"
    api_secret_header_key = "HTTP_ZENTRAL_API_SECRET"
    api_secret = None

    def get_api_secret(self):
        if self.api_secret is None:
            raise ImproperlyConfigured('Missing api_secret')
        else:
            return self.api_secret

    def dispatch(self, request, *args, **kwargs):
        req_api_secret = request.META.get(self.api_secret_header_key, None)
        auth_err = None
        if req_api_secret is None:
            auth_err = 'Missing or empty {} header'.format(self.api_secret_header)
        elif req_api_secret != self.get_api_secret():
            auth_err = 'Wrong {} header value "{}"'.format(self.api_secret_header, req_api_secret)
        if auth_err:
            return HttpResponseForbidden(auth_err)
        self.user_agent = request.META.get("HTTP_USER_AGENT", "")
        self.ip = request.META.get("HTTP_X_REAL_IP", "")
        if request.method == 'POST':
            payload = request.body
            if request.META.get('HTTP_CONTENT_ENCODING', None) in ['zlib', 'gzip']:
                payload = zlib.decompress(payload)
            self.data = json.loads(payload.decode('utf-8'))
        else:
            self.data = None
        return super(CheckAPISecretView, self).dispatch(request, *args, **kwargs)
