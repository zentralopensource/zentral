from gzip import GzipFile
import json
import logging
import zlib
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.views.generic import View
from .http import user_agent_and_ip_address_from_request


logger = logging.getLogger('zentral.utils.api_views')


class APIAuthError(Exception):
    pass


class JSONPostAPIView(View):
    payload_encoding = 'utf-8'

    def check_request_secret(self, request, *args, **kwargs):
        # ALWAYS PASS !
        pass

    def dispatch(self, request, *args, **kwargs):
        try:
            self.check_request_secret(request, *args, **kwargs)
        except APIAuthError as e:
            logger.error("Forbidden: %s", e, extra={'request': request})
            return HttpResponseForbidden()
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
        except APIAuthError as e:
            logger.error("Forbidden: %s", e, extra={'request': request})
            return HttpResponseForbidden()
        response_data = self.do_post(data)
        return JsonResponse(response_data)
