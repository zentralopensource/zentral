import uuid
from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from accounts.models import User
from realms.models import (Realm, RealmEmail, RealmGroup, RealmGroupMapping, RealmTagMapping,
                           RealmUser, RealmUserGroupMembership)
from zentral.contrib.inventory.models import Tag


def force_realm(backend="ldap", enabled_for_login=False, user_portal=False):
    if backend == "ldap":
        config = {
            "host": "ldap.example.com",
            "bind_dn": "uid=zentral,ou=Users,o=yolo,dc=example,dc=com",
            "bind_password": "yolo",
            "users_base_dn": 'ou=Users,o=yolo,dc=example,dc=com',
        }
    elif backend == "openidc":
        config = {
            "client_id": "yolo",
            "client_secret": "fomo",
            "discovery_url": "https://zentral.example.com/.well-known/openid-configuration",
            "extra_scopes": ["profile"],
        }
    elif backend == "saml":
        config = {
            'default_relay_state': "29eb0205-3572-4901-b773-fc82bef847ef",
            'idp_metadata': "<md></md>"
        }
    else:
        raise ValueError("Unknown backend")
    return Realm.objects.create(
        name=get_random_string(12),
        backend=backend,
        config=config,
        username_claim="username",
        email_claim="email",
        enabled_for_login=enabled_for_login,
        user_portal=user_portal,
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


def force_user(username=None, email=None, active=True, remote=False, service_account=False):
    if not username:
        username = get_random_string(12)
    if not email:
        email = get_random_string(12) + "@zentral.com"
    user = User(
        username=username,
        email=email,
        first_name=get_random_string(12),
        last_name=get_random_string(12),
        is_active=active,
        is_remote=remote,
        is_service_account=service_account,
    )
    user.set_password(get_random_string(12))
    user.save()
    return user
