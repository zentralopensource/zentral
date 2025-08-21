import logging
import re
from rest_framework import serializers
import requests
from .base import CertIssuerError, CertIssuer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.base_microsoft_ca")


class BaseMicrosoftCA(CertIssuer):
    kwargs_keys = (
        "url",
        "username",
        "password"
    )
    encrypted_kwargs_paths = (
        ["password"],
    )
    encoding = None  # To be set in subclasses
    regexp = None  # To be set in subclasses

    def get_challenge(self):
        try:
            r = requests.get(self.url, auth=(self.username, self.password))
            r.raise_for_status()
        except Exception as e:
            raise CertIssuerError(f"Request error: {e}")
        else:
            try:
                page_content = r.content.decode(self.encoding)
            except UnicodeDecodeError:
                raise CertIssuerError("Could not decode response.")
            for match in re.finditer(self.regexp, page_content):
                return match.group(1)
        raise CertIssuerError("Could not find challenge in response.")

    def update_acme_payload(
        self, acme_payload, hardware_bound, attest,
        enrollment_session, enrolled_user=None
    ):
        self.update_acme_payload_with_instance(acme_payload, hardware_bound, attest)
        acme_payload["ClientIdentifier"] = self.get_challenge()

    def update_scep_payload(self, scep_payload, enrollment_session, enrolled_user=None):
        self.update_scep_payload_with_instance(scep_payload)
        scep_payload["Challenge"] = self.get_challenge()


class BaseMicrosoftCASerializer(serializers.Serializer):
    url = serializers.URLField()
    username = serializers.CharField()
    password = serializers.CharField()
