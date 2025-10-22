import logging
import uuid
from django.utils.functional import cached_property
from rest_framework import serializers
from urllib.parse import urljoin, urlparse
import requests
from base.utils import deployment_info
from zentral.utils.requests import CustomHTTPAdapter
from .base import CertIssuerError, CertIssuer


logger = logging.getLogger("zentral.contrib.mdm.cert_issuers.digicert")


# Mapping of the fields in an Apple certificate payload subject
# to the fields in a Digicert enrollment request.
# https://github.com/apple/device-management/blob/8d9958d9b54239344e7190e17ddb559416b017e3/declarative/declarations/assets/credentials/scep.yaml#L38  # NOQA
# https://one.digicert.com/mpki/docs/swagger-ui/index.html#/Enrollments/post_mpki_api_v1_enrollment
SUPPORTED_SUBJECT_RDNS = (
    (("CN", "2.5.4.3"), "common_name", False),
    (("C", "2.5.4.6"), "country", False),
    (("2.5.4.13",), "description", True),
    (("0.9.2342.19200300.100.1.25",), "domain_component", True),
    (("2.5.4.46",), "dn_qualifier", False),
    (("1.2.840.113549.1.9.1",), "email", False),
    (("2.5.4.42",), "given_name", True),
    (("L", "2.5.4.7"), "locality", False),
    (("2.5.4.97",), "organization_identifier", False),
    (("O", "2.5.4.10"), "organization_name", False),
    (("OU", "2.5.4.11"), "organization_units", True),
    (("2.5.4.17",), "postal_code", False),
    (("2.5.4.65",), "pseudonym", False),
    (("ST", "2.5.4.8"), "state", False),
    (("2.5.4.9",), "street_address", True),
    (("2.5.4.5",), "serial_number", False),
    (("2.5.4.4",), "surname", True),
    (("2.5.4.12",), "title", True),
    (("2.5.4.45",), "unique_identifier", False),
    (("1.2.840.113549.1.9.2",), "unstructured_name", True),
    (("1.2.840.113549.1.9.8",), "unstructured_address", True),
    (("0.9.2342.19200300.100.1.1",), "user_identifier", False),
)


# https://docs.digicert.com/en/trust-lifecycle-manager/define-policies-to-ensure-compliance/certificate-attributes-and-extensions/unique-attributes.html  # NOQA
SEAT_ID_MAPPING_SUBJECT_ATTRIBUTES = (
    "common_name",
    "email",
    "serial_number",
    "unique_identifier",
    "user_identifier",
    "pseudonym",
    "dn_qualifier",
)

SEAT_ID_MAPPING_SAN_ATTRIBUTES = (
    "rfc822Name",
    "dNSName",
    # Not available in the Apple certificate payloads
    # Other name (GUID)
    # Other name (UPN)
    # Registered ID
)


class Digicert(CertIssuer):
    kwargs_keys = (
        "api_base_url",
        "api_token",
        "profile_guid",
        "business_unit_guid",
        "seat_type",
        "seat_id_mapping",
        "default_seat_email",
    )
    encrypted_kwargs_paths = (
        ["api_token"],
    )
    default_api_base_url = "https://one.digicert.com/mpki/api/"
    default_request_timeout = 15
    default_max_retries = 3
    seat_type_choices = ["USER_SEAT", "DEVICE_SEAT"]
    default_seat_type = "DEVICE_SEAT"
    seat_id_mapping_choices = SEAT_ID_MAPPING_SUBJECT_ATTRIBUTES + SEAT_ID_MAPPING_SAN_ATTRIBUTES
    default_seat_id_mapping = "common_name"

    @cached_property
    def session(self):
        s = requests.Session()
        s.headers.update({'x-api-key': self.api_token,
                          'Content-Type': 'application/json',
                          'User-Agent': deployment_info.user_agent})
        s.mount(self.api_base_url, CustomHTTPAdapter(self.default_request_timeout, self.default_max_retries))
        return s

    def get_seat_id_from_san(self, scep_payload):
        try:
            return scep_payload["SubjectAltName"][self.seat_id_mapping]
        except KeyError:
            raise CertIssuerError(f"Could not get seat ID '{self.seat_id_mapping}' from SAN")

    def get_seat_id_from_subject(self, scep_payload):
        for source_attrs, dest_attr, _ in SUPPORTED_SUBJECT_RDNS:
            if dest_attr != self.seat_id_mapping:
                continue
            for subj_items in scep_payload.get("Subject", []):
                for oid, val in subj_items:
                    if oid in source_attrs:
                        return val
        raise CertIssuerError(f"Could not get seat ID '{self.seat_id_mapping}' from Subject")

    def get_seat_id(self, scep_payload):
        if self.seat_id_mapping in SEAT_ID_MAPPING_SUBJECT_ATTRIBUTES:
            return self.get_seat_id_from_subject(scep_payload)
        elif self.seat_id_mapping in SEAT_ID_MAPPING_SAN_ATTRIBUTES:
            return self.get_seat_id_from_san(scep_payload)
        else:
            raise CertIssuerError(f"Unknown seat ID mapping '{self.seat_id_mapping}'")

    def get_seat_email(self, enrollment_session):
        if enrollment_session.realm_user and enrollment_session.realm_user.email:
            return enrollment_session.realm_user.email
        else:
            return self.default_seat_email

    def get_seat(self, seat_id):
        try:
            r = self.session.get(urljoin(self.api_base_url, f"./v1/seat/{seat_id}"),
                                 params={"seat_type_id": self.seat_type,
                                         "business_unit_id": self.business_unit_guid})
            if r.status_code == 404:
                return
            r.raise_for_status()
        except Exception:
            raise CertIssuerError(f"Could not get seat '{seat_id}'")
        return {k: v for k, v in r.json().items() if k in ("seat_id", "email")}

    def create_seat(self, seat_id, enrollment_session):
        seat_email = self.get_seat_email(enrollment_session)
        try:
            r = self.session.post(urljoin(self.api_base_url, "./v1/seat"),
                                  json={"business_unit_id": self.business_unit_guid,
                                        "seat_type": {"id": self.seat_type},
                                        "seat_id": seat_id,
                                        "seat_name": seat_id,
                                        "email": seat_email})
            r.raise_for_status()
        except Exception:
            raise CertIssuerError(f"Could not create seat '{seat_id}'")
        return {"seat_id": seat_id, "email": seat_email}

    def get_or_create_seat(self, scep_payload, enrollment_session):
        seat_id = self.get_seat_id(scep_payload)
        seat = self.get_seat(seat_id)
        if seat:
            return seat
        return self.create_seat(seat_id, enrollment_session)

    def build_enrollment_request(self, scep_payload, enrollment_session):
        req = {
            "profile": self.profile_guid,
            "seat": self.get_or_create_seat(scep_payload, enrollment_session),
            "attributes": {},
        }
        req_subject = {}
        for subj_items in scep_payload.get("Subject", []):
            for oid, val in subj_items:
                for source_attrs, dest_attr, is_list in SUPPORTED_SUBJECT_RDNS:
                    if dest_attr == self.seat_id_mapping:
                        continue
                    if oid in source_attrs:
                        if is_list:
                            req_subject.setdefault(dest_attr, []).append(val)
                        else:
                            req_subject[dest_attr] = val
                        break
        if req_subject:
            req["attributes"]["subject"] = req_subject
        return req

    def get_challenge(self, scep_payload, enrollment_session):
        try:
            r = self.session.post(
                urljoin(self.api_base_url, "./v1/enrollment"),
                json=self.build_enrollment_request(scep_payload, enrollment_session),
            )
            r.raise_for_status()
        except Exception as e:
            raise CertIssuerError(f"Request error: {e}")
        else:
            try:
                return r.json()["enrollment_code"]
            except Exception:
                raise CertIssuerError("Could get enrollment_code from response")

    def update_acme_payload(*args, **kwargs):
        raise NotImplementedError

    def update_scep_payload(self, scep_payload, enrollment_session, enrolled_user=None):
        self.update_scep_payload_with_instance(scep_payload)
        scep_payload["Challenge"] = self.get_challenge(scep_payload, enrollment_session)


class DigicertSerializer(serializers.Serializer):
    api_base_url = serializers.URLField(default=Digicert.default_api_base_url)
    api_token = serializers.CharField()
    profile_guid = serializers.CharField()
    business_unit_guid = serializers.CharField()
    seat_type = serializers.ChoiceField(
        choices=Digicert.seat_type_choices,
        default=Digicert.default_seat_type,
    )
    seat_id_mapping = serializers.ChoiceField(
        choices=Digicert.seat_id_mapping_choices,
        default=Digicert.default_seat_id_mapping,
    )
    default_seat_email = serializers.EmailField()

    def validate_api_base_url(self, value):
        if not urlparse(value).path.endswith("/api/"):
            raise serializers.ValidationError("URL path must end with '/api/'")
        return value

    def _validate_guid(self, value):
        try:
            return str(uuid.UUID(value)).lower()
        except Exception:
            raise serializers.ValidationError("Not a valid GUID")

    def validate_profile_guid(self, value):
        return self._validate_guid(value)

    def validate_business_unit_guid(self, value):
        return self._validate_guid(value)
