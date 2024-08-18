import base64
import copy
import hashlib
import plistlib
import secrets


def build_password_hash_dict(password, iterations=39999, salt=None):
    # see https://developer.apple.com/documentation/devicemanagement/setautoadminpasswordcommand/command
    # for the compatibility
    password = password.encode("utf-8")
    if salt is None:
        salt = bytearray(secrets.randbits(8) for i in range(32))
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


def serialize_password_hash_dict(password_hash_dict):
    password_hash_dict = copy.deepcopy(password_hash_dict)
    for hash_type, hash_dict in password_hash_dict.items():
        for k, v in hash_dict.items():
            if isinstance(v, str):
                # decode base64 encoded bytes
                hash_dict[k] = base64.b64decode(v.encode("utf-8"))  # → bytes to get <data/> in the plist
    return plistlib.dumps(password_hash_dict).strip()
