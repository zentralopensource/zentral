import json
import logging
import pprint
from django.http import JsonResponse, HttpResponseForbidden
from django.views.generic import View
from . import api_secret
from .events import post_jss_event

logger = logging.getLogger('zentral.contrib.jss.views')


class PostEventView(View):
    def post(self, request, *args, **kwargs):
        req_api_secret = request.META.get('HTTP_ZENTRAL_API_SECRET', None)
        forbidden_msg = None
        if req_api_secret is None:
            forbidden_msg = 'Missing or empty Zentral-API-Secret header'
        elif req_api_secret != api_secret:
            forbidden_msg = 'Wrong Zentral-API-Secret header value "{}"'.format(req_api_secret)
        if forbidden_msg:
            return HttpResponseForbidden(forbidden_msg)
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        ip = request.META.get("HTTP_X_REAL_IP", "")
        data = json.loads(request.body.decode('utf-8'))
        try:
            msn = data['eventType']['eventObject']['serialNumber']
        except KeyError:
            logger.error('JSS event w/o serial number\n%s', pprint.pformat(data))
        else:
            post_jss_event(msn,
                           user_agent,
                           ip,
                           data)
        return JsonResponse({})
