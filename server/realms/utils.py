import logging
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.urls import reverse
from accounts.events import post_group_membership_updates
from .middlewares import SESSION_KEY


logger = logging.getLogger("zentral.realms.utils")


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
        for claim_value in claim_values:
            if not isinstance(claim_value, str):
                claim_value = str(claim_value)
            if realm_group_mapping.separator:
                values = claim_value.split(realm_group_mapping.separator)
            else:
                values = [claim_value]
            if realm_group_mapping.value in values:
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
        post_group_membership_updates(request, mapped_groups - current_groups, current_groups - mapped_groups)


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
    request.session[SESSION_KEY] = str(realm_authentication_session.pk)
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
