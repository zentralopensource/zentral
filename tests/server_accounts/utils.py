from accounts.models import APIToken, Group, ProvisionedRole, User
from django.utils.crypto import get_random_string


def force_role(name=None, provisioning_uid=None):
    role = Group.objects.create(name=name or get_random_string(12))
    if provisioning_uid:
        ProvisionedRole.objects.create(group=role, provisioning_uid=provisioning_uid)
    return role


def force_user_token(user=None, name=None, expiry=None):
    if user is None:
        user = User.objects.create_user(get_random_string(12), "{}@zentral.io".format(get_random_string(12)),
                                        get_random_string(12), is_superuser=False)
    token, _ = APIToken.objects.create_for_user(user, name=name, expiry=expiry)
    return user, token
