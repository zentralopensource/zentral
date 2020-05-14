import base64
import hashlib
import logging
import random
from django.conf import settings
from django.contrib.auth import authenticate, login


logger = logging.getLogger("zentral.realms.utils")


try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


def login_callback(request, realm_user, next_url=None):
    """
    Realm authorization session callback used to log realm users in,
    as Zentral users
    """
    user = authenticate(request=request, realm_user=realm_user)
    if not user:
        raise ValueError("Could not authenticate realm user")
    else:
        request.session.set_expiry(0)
        login(request, user)
    return next_url or settings.LOGIN_REDIRECT_URL


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
