import base64
from datetime import datetime
import hashlib
import logging
import random
import uuid
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.urls import reverse
from accounts.events import AddUserToGroupEvent, RemoveUserFromGroupEvent
from zentral.core.events.base import EventMetadata, EventRequest


logger = logging.getLogger("zentral.realms.utils")


try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


def get_realm_user_mapped_groups(realm_user):
    mapped_groups = set([])
    claims = realm_user.claims
    if "ava" in claims:
        # special case for SAML
        claims = claims["ava"]
    for realm_group_mapping in realm_user.realm.realmgroupmapping_set.select_related("group").all():
        claim_values = claims.get(realm_group_mapping.claim)
        if not isinstance(claim_values, list):
            claim_values = [claim_values]
        for v in claim_values:
            if not isinstance(v, str):
                v = str(v)
            if v == realm_group_mapping.value:
                mapped_groups.add(realm_group_mapping.group)
                break
    return mapped_groups


def _update_remote_user_groups(request, realm_user):
    user = request.user
    if not user.is_remote:
        return
    mapped_groups = get_realm_user_mapped_groups(realm_user)
    current_groups = set(user.groups.all())
    if current_groups != mapped_groups:
        user.groups.set(mapped_groups)
        event_request = EventRequest.build_from_request(request)
        created_at = datetime.utcnow()
        event_uuid = uuid.uuid4()
        event_index = 0
        added_groups = mapped_groups - current_groups
        if added_groups:
            event_metadata = EventMetadata(AddUserToGroupEvent.event_type,
                                           namespace=AddUserToGroupEvent.namespace,
                                           request=event_request,
                                           tags=AddUserToGroupEvent.tags,
                                           uuid=event_uuid,
                                           created_at=created_at)
            for added_group in added_groups:
                event_metadata.index = event_index
                event = AddUserToGroupEvent(
                    event_metadata,
                    {"group": {"pk": added_group.pk, "name": added_group.name}}
                )
                event.post()
                event_index += 1
        removed_groups = current_groups - mapped_groups
        if removed_groups:
            event_metadata = EventMetadata(RemoveUserFromGroupEvent.event_type,
                                           namespace=RemoveUserFromGroupEvent.namespace,
                                           request=event_request,
                                           tags=RemoveUserFromGroupEvent.tags,
                                           uuid=event_uuid,
                                           created_at=created_at)
            for removed_group in removed_groups:
                event_metadata.index = event_index
                event = RemoveUserFromGroupEvent(
                    event_metadata,
                    {"group": {"pk": removed_group.pk, "name": removed_group.name}}
                )
                event.post()
                event_index += 1


def _update_session_realm_info(session, realm_authentication_session):
    session["realm_authentication_session_pk"] = str(realm_authentication_session.pk)
    realm = realm_authentication_session.realm
    session["realm_pk"] = str(realm.pk)
    session["realm_backend"] = realm.backend
    session["realm_name"] = realm.name
    session["realm_user_pk"] = str(realm_authentication_session.user.pk)


def login_callback(request, realm_authentication_session, next_url=None):
    """
    Realm authorization session callback used to log realm users in,
    as Zentral users
    """
    # login
    realm_user = realm_authentication_session.user
    user = authenticate(request=request, realm_user=realm_user)
    if not user:
        raise ValueError("Could not authenticate realm user")

    # update session
    # need to update the session before the login to be able to get the information from the auth signal
    _update_session_realm_info(request.session, realm_authentication_session)
    login(request, user)
    request.session.set_expiry(realm_authentication_session.computed_expiry())

    # apply realm group mappings
    _update_remote_user_groups(request, realm_user)

    return next_url or settings.LOGIN_REDIRECT_URL


def test_callback(request, realm_authentication_session):
    """
    Realm authorization session callback used to test the realm
    """
    return reverse("realms:authentication_session",
                   args=(realm_authentication_session.realm.pk,
                         realm_authentication_session.pk))


def build_password_hash_dict(password):
    # see https://developer.apple.com/documentation/devicemanagement/setautoadminpasswordcommand/command
    # for the compatibility
    password = password.encode("utf-8")
    salt = bytearray(random.getrandbits(8) for i in range(32))
    iterations = 39999
    # see https://github.com/micromdm/micromdm/blob/master/pkg/crypto/password/password.go macKeyLen !!!
    # Danke github.com/groob !!!
    dklen = 128

    dk = hashlib.pbkdf2_hmac("sha512", password, salt, iterations, dklen=dklen)
    return {
        "SALTED-SHA512-PBKDF2": {
            "entropy": base64.b64encode(dk).decode("ascii").strip(),
            "salt": base64.b64encode(salt).decode("ascii").strip(),
            "iterations": iterations
        }
    }
