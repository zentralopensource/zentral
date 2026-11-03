from django.db import migrations


ROLE_NAME = "SCIM provisioning"
# the legacy permissions of the SCIM policy of the documentation before provisionRealm
SCIM_PERMS = frozenset(
    f"realms.{operation}_{model}"
    for model in ("realmuser", "realmgroup")
    for operation in ("view", "add", "change", "delete")
)


def unique_name(model, name):
    candidate = name
    i = 1
    while model.objects.filter(name=candidate).exists():
        i += 1
        candidate = f"{name} ({i})"
    return candidate


def give_provision_realm_to_the_scim_accounts(apps, schema_editor):
    Realm = apps.get_model("realms", "Realm")
    realms = list(Realm.objects.filter(scim_enabled=True).order_by("name", "pk"))
    if not realms:
        return

    # the legacy permissions exist only as decisions of the engine of this release
    from pbac.cedar import policies_cache
    from pbac.engine import engine
    from pbac.entities import Principal, Request

    def legacy_perms(account):
        principal = Principal.from_user(account)
        requests = {perm: Request(principal, action, engine.system_any_resource)
                    for perm, action in engine.legacy_perm_actions.items()}
        engine.authorize_requests(list(requests.values()))
        return {perm for perm, request in requests.items() if request.is_authorized}

    # no notifier: its reconnect timer would keep the migrate process alive without Redis
    with_sync = policies_cache.with_sync
    policies_cache.with_sync = False
    try:
        User = apps.get_model("accounts", "User")
        # exactly these permissions: an account with more is an integration or an admin that the policies
        # also let call SCIM, not the account of the IdP
        accounts = [
            account
            for account in User.objects.filter(is_service_account=True, is_active=True).prefetch_related("groups")
            if legacy_perms(account) == SCIM_PERMS
        ]
    finally:
        policies_cache.with_sync = with_sync
        policies_cache.clear()

    # one role for all the realms: each SCIM account could write each SCIM realm before
    Group = apps.get_model("auth", "Group")
    role = Group.objects.create(name=unique_name(Group, ROLE_NAME))
    for account in accounts:
        account.groups.add(role)

    Policy = apps.get_model("accounts", "Policy")
    for realm in realms:
        Policy.objects.create(
            name=unique_name(Policy, f"{ROLE_NAME}: {realm.name}"),
            description=(
                f"Made by the upgrade to Realms::Action::\"provisionRealm\". The service accounts of the "
                f"{role.name} role write the users and the groups of the {realm.name} realm through SCIM. "
                "Remove from the role the accounts that do not call SCIM."
            ),
            # is ServiceAccount: a role mapping can give the role to the remote users
            source=(
                "permit (\n"
                f"  principal is ServiceAccount in Role::\"{role.pk}\",\n"
                "  action == Realms::Action::\"provisionRealm\",\n"
                f"  resource == Realms::Realm::\"{realm.pk}\"\n"
                ");"
            ),
        )


class Migration(migrations.Migration):

    dependencies = [
        ('realms', '0016_realmuser_scim_updated_at'),
        ('accounts', '0026_superusers_have_no_api_token'),
    ]

    operations = [
        migrations.RunPython(give_provision_realm_to_the_scim_accounts, migrations.RunPython.noop),
    ]
