import logging
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.core.signing import BadSignature, Signer
from zentral.contrib.mdm.models import EnrolledUser, Package
from .exceptions import (TokenSessionNotFoundError,
                         TokenSignatureError,
                         TokenTargetNotFoundError,
                         TokenUserNotFoundError)
from .utils import _check_device_inactive


__all__ = [
    "dump_package_file_token",
    "dump_package_manifest_token",
    "load_package_file_token",
    "load_package_manifest_token",
]


logger = logging.getLogger("zentral.contrib.mdm.declarations.packages")


TOKEN_SALT_MANIFEST = "zentral_mdm_package_manifest"
TOKEN_SALT_FILE = "zentral_mdm_package_file"


# Signer (not signing.dumps / TimestampSigner) is intentional: the manifest URL
# must be a stable function of (session, package) so the ManifestURL embedded
# in MDM commands and DDM declarations does not change every time we regenerate
# it. signing.dumps mixes in a base-62 epoch-second timestamp, which would
# silently produce a different token whenever the wall clock advanced. We use
# the same scheme for the file token so both URLs are deterministic.


def _dump_token(enrollment_session, target, package_pk, salt):
    if not isinstance(package_pk, str):
        package_pk = str(package_pk)
    payload = {
        "pk": package_pk,
        "esm": enrollment_session._meta.model_name,
        "espk": enrollment_session.pk,
    }
    if target.enrolled_user:
        payload["eupk"] = target.enrolled_user.pk
    return Signer(salt=salt).sign_object(payload)


def _load_token(token, salt):
    try:
        payload = Signer(salt=salt).unsign_object(token)
    except BadSignature as e:
        raise TokenSignatureError(str(e)) from e
    try:
        package = Package.objects.get(pk=payload["pk"])
    except Package.DoesNotExist:
        raise TokenTargetNotFoundError(payload["pk"])
    try:
        es_ct = ContentType.objects.get_by_natural_key("mdm", payload["esm"])
        enrollment_session = (es_ct.model_class()
                                   .objects
                                   .select_related("enrolled_device", "realm_user")
                                   .get(pk=payload["espk"]))
    except ObjectDoesNotExist:
        raise TokenSessionNotFoundError(package, payload["esm"], payload["espk"])
    _check_device_inactive(package, enrollment_session)
    enrolled_user = None
    if "eupk" in payload:
        try:
            enrolled_user = EnrolledUser.objects.get(pk=payload["eupk"])
        except EnrolledUser.DoesNotExist:
            raise TokenUserNotFoundError(package, enrollment_session, payload["eupk"])
    return package, enrollment_session, enrolled_user


def dump_package_manifest_token(enrollment_session, target, package_pk):
    return _dump_token(enrollment_session, target, package_pk, TOKEN_SALT_MANIFEST)


def load_package_manifest_token(token):
    return _load_token(token, TOKEN_SALT_MANIFEST)


def dump_package_file_token(enrollment_session, target, package_pk):
    return _dump_token(enrollment_session, target, package_pk, TOKEN_SALT_FILE)


def load_package_file_token(token):
    return _load_token(token, TOKEN_SALT_FILE)
