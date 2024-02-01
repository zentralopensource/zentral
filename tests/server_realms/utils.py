import uuid
from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from realms.models import (Realm, RealmEmail, RealmGroup, RealmGroupMapping, RealmTagMapping,
                           RealmUser, RealmUserGroupMembership)
from zentral.contrib.inventory.models import Tag


def force_realm():
    return Realm.objects.create(
        name=get_random_string(12),
        backend="ldap",
        username_claim="username",
        email_claim="email"
    )


def force_realm_user(
    realm=None,
    email_count=0,
    group=None,
):
    if not realm:
        realm = force_realm()
    username = get_random_string(12)
    email = f"{username}@zentral.com"
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        first_name=get_random_string(12),
        last_name=get_random_string(12),
        email=email,
        scim_external_id=str(uuid.uuid4()).replace("-", "")[:10] if realm.scim_enabled else None,
        scim_active=realm.scim_enabled,
    )
    for idx in range(email_count):
        RealmEmail.objects.create(user=realm_user,
                                  primary=idx == 0,
                                  type="work",
                                  email=email if idx == 0 else f"{get_random_string(12)}@zentral.com")
    if group:
        RealmUserGroupMembership.objects.create(user=realm_user, group=group)
    return realm, realm_user


def force_realm_group(realm=None, parent=None, display_name=None):
    if not realm:
        realm = force_realm()
    return RealmGroup.objects.create(
        realm=realm,
        display_name=display_name or get_random_string(12),
        parent=parent,
        scim_external_id=str(uuid.uuid4()).replace("-", "")[:10] if realm.scim_enabled else None,
    )


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


def force_realm_tag_mapping(realm=None, group_name=None, tag=None):
    if not realm:
        realm = force_realm()
    if not group_name:
        group_name = get_random_string(12)
    if not tag:
        tag = Tag.objects.create(name=get_random_string(12))
    realm_tag_mapping = RealmTagMapping.objects.create(
        realm=realm,
        group_name=group_name,
        tag=tag
    )
    return realm, realm_tag_mapping
