import logging
import pprint
from django.http import JsonResponse
from zentral.utils.api_views import CheckAPISecretView
from . import api_secret
from .events import post_jss_event

logger = logging.getLogger('zentral.contrib.jss.views')


class PostEventView(CheckAPISecretView):
    api_secret = api_secret

    def post(self, request, *args, **kwargs):
        try:
            msn = self.data['eventType']['eventObject']['serialNumber']
        except KeyError:
            logger.debug('JSS event w/o serial number\n%s', pprint.pformat(self.data))
        else:
            post_jss_event(msn,
                           self.user_agent,
                           self.ip,
                           self.data)
        return JsonResponse({})
