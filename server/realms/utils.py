import base64
from datetime import datetime
import hashlib
import logging
import random
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.urls import reverse


logger = logging.getLogger("zentral.realms.utils")


try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


def login_callback(request, realm_authentication_session, next_url=None):
    """
    Realm authorization session callback used to log realm users in,
    as Zentral users
    """
    # session expiry
    # default to 5 min, to be really annoying!
    session_expiry = 5 * 60
    if realm_authentication_session.realm.login_session_expiry is not None:
        # the session expiry configured in the realm takes precedence
        session_expiry = realm_authentication_session.realm.login_session_expiry
    elif realm_authentication_session.expires_at:
        # fall back to the session expiry attached to the realm authentication session
        expiry_delta = realm_authentication_session.expires_at - datetime.utcnow()
        session_expiry = expiry_delta.days * 86400 + expiry_delta.seconds
        if session_expiry < 0:
            # should not happen, but who knows
            raise ValueError("The SSO session has already expired")
    else:
        logger.error("No session expiry found in the realm %s authentication session. "
                     "Use default expiry of %s seconds.",
                     realm_authentication_session.realm, session_expiry)

    # login
    realm_user = realm_authentication_session.user
    user = authenticate(request=request, realm_user=realm_user)
    if not user:
        raise ValueError("Could not authenticate realm user")
    else:
        request.session.set_expiry(session_expiry)
        request.session["_realm_authentication_session"] = str(realm_authentication_session.uuid)
        login(request, user)
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
