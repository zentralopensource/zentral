import binascii
import string
from django.utils.crypto import get_random_string

ALLOWED_CHARS = string.digits + string.ascii_letters
ENTROPY = 178
RANDOM_LENGTH = 30  # math.ceil(ENTROPY / math.log(len(ALLOWED_CHARS), 2))
CHECKSUM_LENGTH = 6
PREFIX_LENGTH = 4  # ztlx

USER_API_TOKEN = 'u'
SERVICE_ACCOUNT_API_TOKEN = 's'
RESERVED_PREFIXES = (USER_API_TOKEN, SERVICE_ACCOUNT_API_TOKEN)


def generate_ztl_token(prefix: str) -> str:
    if prefix not in RESERVED_PREFIXES:
        raise ValueError("Unknown token prefix")
    suffix = get_random_string(RANDOM_LENGTH, allowed_chars=ALLOWED_CHARS)
    first_part = f"ztl{prefix}_{suffix}"
    checksum = _generate_checksum(first_part)
    return f"{first_part}{checksum}"


def verify_ztl_token(token: str, valid_prefixes: list[str]) -> bool:
    if not token:
        return False

    if not valid_prefixes:
        return False

    # check the prefix is valid
    provided_prefix = _prefix(token)
    if not valid_prefixes or provided_prefix not in valid_prefixes:
        return False

    # the extracted checksum
    provided_checksum = _checksum(token)
    if not provided_checksum:
        return False

    # the token without the final checksum
    token_without_checksum = _wo_checksum(token)
    if not token_without_checksum:
        return False
    calculated_checksum = _generate_checksum(token_without_checksum)

    # compare calculated and provided checksum
    return calculated_checksum == provided_checksum


def _generate_checksum(string: str) -> str:
    checksum = binascii.crc32(string.encode('UTF-8'))
    return _to_base62(checksum).zfill(CHECKSUM_LENGTH)


def _prefix(token: str) -> str:
    return token[PREFIX_LENGTH-1:PREFIX_LENGTH]


def _checksum(token: str) -> str:
    return token[-CHECKSUM_LENGTH:] if len(token) > CHECKSUM_LENGTH else ''


def _wo_checksum(token: str) -> str:
    return token[0:-CHECKSUM_LENGTH] if len(token) > CHECKSUM_LENGTH + RANDOM_LENGTH else ''


def _to_base62(num: int) -> str:
    chars = ALLOWED_CHARS
    if num == 0:
        return chars[0]
    base62 = []
    while num > 0:
        num, rem = divmod(num, 62)
        base62.append(chars[rem])
    return "".join(reversed(base62))
