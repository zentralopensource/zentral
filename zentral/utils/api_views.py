from datetime import datetime
import gzip
import json
import os
import tempfile
import zlib
from django.conf import settings
from django.views.generic import View
from django.http import HttpResponseForbidden
from zentral.core.exceptions import ImproperlyConfigured


class CheckAPISecretView(View):
    api_secret_header = "Zentral-API-Secret"
    api_secret_header_key = "HTTP_ZENTRAL_API_SECRET"
    api_secret = None
    # json post payload dump for debugging
    dump_post_payloads = getattr(settings, 'DEBUG_ZENTRAL_API_REQUEST', settings.DEBUG)
    post_payloads_dir = None

    def get_post_payload_dump_dir(self, request):
        dirpath = self.post_payloads_dir
        if not dirpath:
            dirpath = os.path.join('/tmp/', 'POST{}'.format(request.path.replace('/', '_-_')))
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        return dirpath

    def dump_post_payload(self, request):
        if not self.dump_post_payloads:
            return
        dirpath = self.get_post_payload_dump_dir(request)
        fh, fname = tempfile.mkstemp(suffix='.json.gz',
                                     prefix=datetime.utcnow().strftime('%Y%m%d_%H%M%S_'),
                                     dir=dirpath)
        os.fdopen(fh).close()
        f = gzip.GzipFile(fname, 'wb')
        f.write(json.dumps(self.data, ensure_ascii=True,
                           sort_keys=True, indent=2, separators=(',', ': ')).encode('utf-8'))
        f.close()

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
            self.dump_post_payload(request)
        else:
            self.data = None
        return super(CheckAPISecretView, self).dispatch(request, *args, **kwargs)
