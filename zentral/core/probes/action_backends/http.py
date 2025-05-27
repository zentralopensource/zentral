import logging
from django.utils.functional import cached_property
import requests
from rest_framework import serializers
from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter
from .base import BaseAction


logger = logging.getLogger("zentral.core.probes.action_backends.http")


class HTTPPostActionHeaderSerializer(serializers.Serializer):
    name = serializers.CharField()
    value = serializers.CharField()


class HTTPPostActionSerializer(serializers.Serializer):
    url = serializers.URLField()
    username = serializers.CharField(required=False, allow_null=True)
    password = serializers.CharField(required=False, allow_null=True)
    headers = HTTPPostActionHeaderSerializer(many=True, required=False)

    @staticmethod
    def _clean_dict(d):
        for k in ("username", "password"):
            if k in d and d[k] is None:
                d.pop(k)
        if "headers" in d and not d["headers"]:
            d.pop("headers")

    def validate(self, data):
        self._clean_dict(data)
        return data

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        self._clean_dict(ret)
        return ret


class HTTPPost(BaseAction):
    kwargs_keys = ("headers", "url", "username", "password")
    encrypted_kwargs_paths = (["headers", "*", "value"], ["password"])
    timeout = 10
    retries = 2

    def load(self):
        super().load()
        if not self.headers:
            self.headers = []

    @cached_property
    def session(self):
        session = requests.Session()
        if self.username and self.password:
            session.auth = (self.username, self.password)
        for header in self.headers:
            session.headers[header["name"]] = header["value"]
        session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": deployment_info.user_agent,
        })
        adapter = CustomHTTPAdapter(self.timeout, self.retries)
        session.mount("https://", adapter)
        return session

    def trigger(self, event, probe):
        r = self.session.post(self.url, json=event.serialize())
        r.raise_for_status()
