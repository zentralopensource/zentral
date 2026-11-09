import base64
from enum import Enum
import zlib
from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.core.validators import ValidationError, validate_ipv46_address


def user_agent_and_ip_address_from_request(request):
    user_agent = request.META.get('HTTP_USER_AGENT', "")
    ip_address = request.META.get('HTTP_X_REAL_IP', "")
    try:
        validate_ipv46_address(ip_address)
    except ValidationError:
        ip_address = request.META.get('REMOTE_ADDR', None)
    return user_agent, ip_address


def basic_auth_username_and_password_from_request(request):
    auth_header = request.META.get("HTTP_AUTHORIZATION", None)
    if not auth_header:
        raise ValueError("Missing Authorization header")
    if isinstance(auth_header, str):
        auth_header = auth_header.encode("utf-8")
    try:
        scheme, params = auth_header.split()
        assert scheme.lower() == b"basic"
        decoded_params = base64.b64decode(params)
        username, password = decoded_params.split(b":", 1)
    except Exception:
        raise ValueError("Invalid basic authentication header")
    return username, password


class Compression(Enum):
    ZLIB = zlib.MAX_WBITS
    GZIP = 16 + zlib.MAX_WBITS


class RequestBodyError(Exception):
    # the response gets the message of the class, never one built from the request or another exception
    status = 400
    message = "Invalid request body"


class UnsupportedContentEncoding(RequestBodyError):
    status = 415
    message = "Unsupported content encoding"


class InvalidCompressedBody(RequestBodyError):
    message = "Invalid compressed request body"


class RequestBodyTooLarge(RequestBodyError):
    status = 413
    message = "Request body too large"


def read_request_body(request, encodings, max_size=None):
    content_encoding = request.META.get("HTTP_CONTENT_ENCODING", "").strip().lower()
    compression = None
    if content_encoding and content_encoding != "identity":
        try:
            compression = encodings[content_encoding]
        except KeyError:
            raise UnsupportedContentEncoding
    if max_size is None:
        max_size = settings.DATA_UPLOAD_MAX_MEMORY_SIZE
    elif int(request.META.get("CONTENT_LENGTH") or 0) > max_size:
        # checked before the body is read, like Django does for its own limit
        raise RequestBodyTooLarge
    try:
        body = request.body
    except RequestDataTooBig:
        raise RequestBodyTooLarge
    if compression is None:
        return body
    # the decompressed body gets the same limit as the received body.
    # A small compressed body can expand to many times its size.
    decompressor = zlib.decompressobj(compression.value)
    try:
        data = decompressor.decompress(body, 0 if max_size is None else max_size + 1)
    except zlib.error:
        raise InvalidCompressedBody
    if max_size is not None and len(data) > max_size:
        raise RequestBodyTooLarge
    if not decompressor.eof or decompressor.unused_data:
        raise InvalidCompressedBody
    return data
