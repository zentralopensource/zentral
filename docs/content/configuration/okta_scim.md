---
title: Okta - SCIM
weight: 160
---

This is a quick guide to help synchronize [Okta](https://www.okta.com/) users and groups with Zentral using [SCIM](https://developer.okta.com/docs/concepts/scim/).

## Update the Zentral realm

First you need to configure an [OKTA realm](okta_saml.md), with the `SCIM enabled` option. If you already have a realm, you can update it and enable SCIM. After you save the realm, you will be redirected to a detail view, with the `SCIM root URL`. This is the URL that you will need to configure the SCIM integration in Okta.

## Provision a Zentral service account

The SCIM synchronization is part of the Zentral API. To let Okta authenticate with Zentral, you need to set up a Zentral service account and a PBAC policy authorizing it.

### Service account

A Zentral service account is a Zentral account that cannot log into the admin console. Only a service account can call the SCIM endpoints: Zentral refuses the API token of a user with a 403 error, whatever the policies say.

1. [Create a service account](../apps/core.md#service-accounts) for your SCIM integration.
2. Give it a role that you use for SCIM only, for example `SCIM provisioning`.
3. [Add an API token](../apps/core.md#api-tokens) to it from its detail page. The token is displayed once, and you will need it later to configure the Okta application.
4. Ask a superuser to write the policy below.

### Policy

The SCIM endpoints check one action, `Realms::Action::"provisionRealm"`, on the realm of the SCIM URL. This action gives all the SCIM operations: read, create and update the realm users, and read, create, update and delete the realm groups and their members.

- The realm user and realm group actions, for example `Realms::Action::"updateRealmGroup"`, are for the console pages only. They give no access to the SCIM endpoints.
- `provisionRealm` is in no action group. A policy that gives `Action::"GlobalAdminActions"` does not give it. A policy with a bare `action` gives it.
- The realm groups give roles to the users. So, after a policy gives `provisionRealm` to a service account, only a superuser can make its API tokens and its token issuers.

Ask a superuser to write a [PBAC policy](pbac.md) for each SCIM realm:

```
permit (
  principal is ServiceAccount in Role::"<role-pk>",
  action == Realms::Action::"provisionRealm",
  resource == Realms::Realm::"<realm-uuid>"
);
```

Substitute `<role-pk>` with the pk of the role of the service account, and `<realm-uuid>` with the UUID of the realm, from the URL of its detail page. Keep `is ServiceAccount`: a role mapping can give the role to a user that a realm login makes.

### The upgrade to `provisionRealm`

Before `provisionRealm`, the SCIM endpoints used the realm user and realm group actions of the console. This documentation gave the SCIM service account a policy with eight of them: `createRealmGroup`, `updateRealmGroup`, `deleteRealmGroup`, `viewRealmGroup`, `createRealmUser`, `updateRealmUser`, `deleteRealmUser` and `viewRealmUser`. The upgrade does these steps, when at least one realm has SCIM enabled:

1. It makes the `SCIM provisioning` role, or `SCIM provisioning (2)` if the name is taken.
2. It adds to the role each active service account whose legacy permissions are exactly these eight. It does not check the typed actions, for example of MDM: the role only gives `provisionRealm`. An account with more actions, for example in an Editor role, or in the role of a Terraform or a CI integration, is not added: the upgrade cannot tell it from an integration that the policies also let call SCIM.
3. It writes the policy above for each realm with SCIM enabled, with the name `SCIM provisioning: <realm name>`.

Before the upgrade, give your SCIM service account a role with only the policy of the eight actions, and remove it from the other roles. The upgrade then adds it to the `SCIM provisioning` role, and SCIM keeps working. If you do not, a superuser adds the account to the `SCIM provisioning` role after the upgrade, and SCIM is refused until then.

The existing tokens keep working. Before the upgrade, each SCIM account could write each SCIM realm, and the role and the policies keep this. After the upgrade:

- To limit an account to one realm, make one role for each realm, and change the policies.
- When you enable SCIM on another realm, a superuser writes its policy.
- Remove the old policy of the eight actions: SCIM does not use it anymore.

## Update the Okta Application

### Add SCIM provisioning

In the `General` tab of the Okta application, click `Edit`, select `SCIM` in the `Provisioning` section and click `SAVE`.

### Choose the provisioning options

Open the `Provisioning` tab of the Okta application, click `Edit`. Use the `SCIM root URL` from the Zentral realm detail page as `SCIM connector base URL`.

Set `userName` as `Unique identifier field for users`.

Under `Supported provisioning actions`, choose `Push New Users`, `Push Profile Updates` and `Push Groups`. The synchronization is only one-way, from Okta to Zentral.

Select the `HTTP Header` authentication, and use the API token of the service account you have just created as bearer token.

After you have saved the form, open the `To App` sub tab. Make sure that the `Create Users`, `Update User Attributes` and `Deactivate Users` options are enabled. The `Sync Password` option must be disabled. In the `Attribute Mappings` section, make sure that you have the following required mappings: `userName`, `email`, and `emailType`.

### Configure the groups to be pushed

**IMPORTANT** Use [a different group](https://help.okta.com/en-us/content/topics/users-groups-profiles/app-assignments-group-push.htm) for application assignment in Okta. The group used for application assignment cannot be pushed to Zentral.

To push an Okta group to Zentral, open the `Push Groups` tab of the Okta application. Click on the `Push Groups` dropdown, look for the group by name or rule, select it. There will probably be no match for the group in Zentral, so the `Create Group` option is displayed, with the named of the group that will be created in Zentral greyed out. You can save this mapping or save and add another one.
