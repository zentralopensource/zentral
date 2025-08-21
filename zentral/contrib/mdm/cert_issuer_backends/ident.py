import logging
from django.utils.functional import cached_property
from rest_framework import serializers
import requests
from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter
from .base import CertIssuerError, CertIssuer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.ident")


class IDent(CertIssuer):
    kwargs_keys = (
        "url",
        "bearer_token",
        "request_timeout",
        "max_retries",
    )
    encrypted_kwargs_paths = (
        ["bearer_token"],
    )
    default_request_timeout = 30
    default_max_retries = 3

    @cached_property
    def session(self):
        s = requests.Session()
        s.headers.update({'Authorization': f'Bearer {self.bearer_token}',
                          'Content-Type': 'application/json',
                          'User-Agent': deployment_info.user_agent})
        s.mount(self.url, CustomHTTPAdapter(self.request_timeout, self.max_retries))
        return s

    @staticmethod
    def get_csr_config(subject, sans, key_usage):
        csr_config = {}
        # Subject
        csr_config_subj = {}
        for subj_items in subject:
            for oid, val in subj_items:
                if oid in ("CN", "2.5.4.3"):
                    if "common_name" not in csr_config_subj:
                        csr_config_subj["common_name"] = val
                elif oid == "2.5.4.5":  # Serial Number
                    if "serial_number" not in csr_config_subj:
                        csr_config_subj["serial_number"] = val
                elif oid in ("C", "2.5.4.6"):
                    csr_config_subj.setdefault("country", []).append(val)
                elif oid in ("O", "2.5.4.10"):
                    csr_config_subj.setdefault("organization", []).append(val)
                elif oid in ("OU", "2.5.4.11"):
                    csr_config_subj.setdefault("organizational_unit", []).append(val)
        if csr_config_subj:
            csr_config["subject"] = csr_config_subj
        # SANs
        csr_config_sans = {}
        for payload_attr, csr_config_attr in (("rfc822Name", "email_addresses"),
                                              ("dNSName", "dns_names"),
                                              ("ntPrincipalName", "nt_principal_names")):
            val = sans.get(payload_attr)
            if val:
                csr_config_sans.setdefault(csr_config_attr, []).append(val)
        if csr_config_sans:
            csr_config["subject_alternative_names"] = csr_config_sans
        # KeyUsage
        if isinstance(key_usage, int):
            csr_config["key_usage"] = key_usage
        return csr_config

    def get_challenge(self, subject, sans, key_usage):
        csr_config = self.get_csr_config(subject, sans, key_usage)
        try:
            r = self.session.post(self.url, json=csr_config)
            r.raise_for_status()
            return r.json()["challenge"]
        except Exception as e:
            raise CertIssuerError(f"Request error: {e}")

    def update_acme_payload(
        self, acme_payload, hardware_bound, attest,
        enrollment_session, enrolled_user=None
    ):
        self.update_acme_payload_with_instance(acme_payload, hardware_bound, attest)
        acme_payload["ClientIdentifier"] = self.get_challenge(
            acme_payload.get("Subject", []),
            acme_payload.get("SubjectAltName", {}),
            acme_payload.get("UsageFlags")
        )

    def update_scep_payload(self, scep_payload, enrollment_session, enrolled_user=None):
        self.update_scep_payload_with_instance(scep_payload)
        scep_payload["Challenge"] = self.get_challenge(
            scep_payload.get("Subject", []),
            scep_payload.get("SubjectAltName", {}),
            scep_payload.get("Key Usage"),
        )


class IDentSerializer(serializers.Serializer):
    url = serializers.URLField()
    bearer_token = serializers.CharField()
    request_timeout = serializers.IntegerField(
        min_value=1,
        default=IDent.default_request_timeout,
    )
    max_retries = serializers.IntegerField(
        min_value=1,
        default=IDent.default_max_retries,
    )
