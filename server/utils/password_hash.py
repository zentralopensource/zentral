import base64
import hashlib
import logging
import random


logger = logging.getLogger("zentral.base.utils.password_hash")


try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


def build_password_hash_dict(password):
    # see https://developer.apple.com/documentation/devicemanagement/setautoadminpasswordcommand/command
    # for the compatibility
    password = password.encode("utf-8")
    salt = bytearray(random.getrandbits(8) for i in range(32))
    iterations = 39999
    dk = hashlib.pbkdf2_hmac("sha512", password, salt, iterations)
    return {
        "SALTED-SHA512-PBKDF2": {
            "entropy": base64.b64encode(dk).decode("ascii").strip(),
            "salt": base64.b64encode(salt).decode("ascii").strip(),
            "iterations": iterations
        }
    }
