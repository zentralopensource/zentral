import logging
from django.utils.functional import cached_property
import requests
from rest_framework import serializers
from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter
from .base import BaseAction


logger = logging.getLogger("zentral.core.probes.action_backends.slack")


class SlackIncomingWebhookActionSerializer(serializers.Serializer):
    url = serializers.URLField()


class SlackIncomingWebhook(BaseAction):
    kwargs_keys = ("url",)
    encrypted_kwargs_paths = (["url"],)
    timeout = 10
    retries = 2

    @cached_property
    def session(self):
        session = requests.Session()
        session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": deployment_info.user_agent,
        })
        adapter = CustomHTTPAdapter(self.timeout, self.retries)
        session.mount("https://", adapter)
        return session

    def trigger(self, event, probe):
        r = self.session.post(
            self.url,
            json={'text': '\n\n'.join([event.get_notification_subject(probe),
                                       event.get_notification_body(probe)])}
        )
        r.raise_for_status()
