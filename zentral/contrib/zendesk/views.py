import logging
from zentral.utils.api_views import JSONPostAPIView, verify_secret
from .events import post_zendesk_event

logger = logging.getLogger('zentral.contrib.zendesk.views')


class PostEventView(JSONPostAPIView):
    def check_data_secret(self, data):
        data = verify_secret(data.pop('zentral_api_secret', None), "zentral.contrib.zendesk")
        self.business_unit = data.get('business_unit', None)

    def do_post(self, data):
        post_zendesk_event(self.user_agent, self.ip, data)
        return {"status": "OK"}
