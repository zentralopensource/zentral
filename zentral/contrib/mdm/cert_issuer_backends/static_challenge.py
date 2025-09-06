import logging
from rest_framework import serializers
from .base import CertIssuer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.static_challenge")


class StaticChallengeSerializer(serializers.Serializer):
    challenge = serializers.CharField()


class StaticChallenge(CertIssuer):
    kwargs_keys = (
        "challenge",
    )
    encrypted_kwargs_paths = (
        ["challenge"],
    )

    def update_acme_payload(
        self, acme_payload, hardware_bound, attest,
        enrollment_session, enrolled_user=None
    ):
        self.update_acme_payload_with_instance(acme_payload, hardware_bound, attest)
        acme_payload["ClientIdentifier"] = self.challenge

    def update_scep_payload(self, scep_payload, enrollment_session, enrolled_user=None):
        self.update_scep_payload_with_instance(scep_payload)
        scep_payload["Challenge"] = self.challenge
