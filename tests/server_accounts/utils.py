from django.utils.crypto import get_random_string
from accounts.models import Group, ProvisionedRole


def force_role(name=None, provisioning_uid=None):
    role = Group.objects.create(name=name or get_random_string(12))
    if provisioning_uid:
        ProvisionedRole.objects.create(group=role, provisioning_uid=provisioning_uid)
    return role
