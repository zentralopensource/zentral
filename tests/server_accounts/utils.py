from cedarpy import format_policies
from django.utils.crypto import get_random_string

from accounts.models import APIToken, Group, Policy, ProvisionedRole, User


def force_policy(provisioning_uid=None):
    return Policy.objects.create(
        provisioning_uid=provisioning_uid,
        name=get_random_string(12),
        description=get_random_string(12),
        source=format_policies(
            'permit (principal in Role::"0", action, resource);'
        )
    )


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
