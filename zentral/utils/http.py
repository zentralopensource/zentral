import base64
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
