from django.core.validators import ValidationError, validate_ipv46_address


def user_agent_and_ip_address_from_request(request):
    user_agent = request.META.get('HTTP_USER_AGENT', "")
    ip_address = request.META.get('HTTP_X_REAL_IP', "")
    try:
        validate_ipv46_address(ip_address)
    except ValidationError:
        ip_address = request.META.get('REMOTE_ADDR', None)
    return user_agent, ip_address
