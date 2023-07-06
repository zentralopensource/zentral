from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmGroupMapping, RealmUser


def force_realm():
    return Realm.objects.create(
        name=get_random_string(12),
        backend="ldap",
        username_claim="username",
        email_claim="email"
    )


def force_realm_user(realm=None):
    if not realm:
        realm = force_realm()
    username = get_random_string(12)
    email = f"{username}@example.com"
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        email=email,
    )
    return realm, realm_user


def force_realm_group_mapping(realm=None, group=None):
    if not realm:
        realm = force_realm()
    if not group:
        group = Group.objects.create(name=get_random_string(12))
    realm_group_mapping = RealmGroupMapping.objects.create(
        realm=realm,
        claim=get_random_string(12),
        value=get_random_string(12),
        group=group
    )
    return realm, realm_group_mapping
