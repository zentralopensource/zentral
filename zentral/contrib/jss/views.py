import logging
import pprint
from zentral.utils.api_views import SignedRequestHeaderJSONPostAPIView
from .events import post_jss_event

logger = logging.getLogger('zentral.contrib.jss.views')


class PostEventView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral.contrib.jss"

    def do_post(self, data):
        try:
            msn = data['eventType']['eventObject']['serialNumber']
        except KeyError:
            logger.debug('JSS event w/o serial number\n%s', pprint.pformat(data))
        else:
            post_jss_event(msn,
                           self.user_agent,
                           self.ip,
                           data)
        return {}
