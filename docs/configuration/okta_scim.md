# Okta - SCIM integration

This is a quick guide to help synchronize [Okta](https://www.okta.com/) users and groups with Zentral using [SCIM](https://developer.okta.com/docs/concepts/scim/).

## Update the Zentral realm

First you need to configure an [OKTA realm](../okta_saml/), with the `SCIM enabled` option. If you already have a realm, you can update it and enable SCIM. After you save the realm, you will be redirected to a detail view, with the `SCIM root URL`. This is the URL that you will need to configure the SCIM integration in Okta.

## Provision a Zentral service account

The SCIM synchronization is part of the Zentral API. To let Okta authenticate with Zentral, you need to setup a Zentral group and a Zentral service account.

### Group

In Zentral, groups are used to give permissions to the users or service accounts. Create a group with the following permissions:

* `realms.realmgroup` add, change, delete, view
* `realms.realmuser` add, change, delete, view

### Service account

A Zentral service account is a Zentral user that cannot log into the admin console. Create a user for your SCIM integration. Pick a name, a description, and add it to the group you have just created. Do not forget to note the API token. You will need it later to configure the Okta application.

## Update the Okta Application

### Add SCIM provisioning

In the `General` tab of the Okta application, click `Edit`, select `SCIM` in the `Provisioning` section and click `SAVE`.

### Choose the provisioning options

Open the `Provisioning` tab of the Okta application, click `Edit`. Use the `SCIM root URL` from the Zentral realm detail page as `SCIM connector base URL`.

Under `Supported provisioning actions`, choose `Push New Users`, `Push Profile Updates` and `Push Groups`. The synchronization is only one-way, from Okta to Zentral.

Select the `HTTP Header` authentication, and use the API token of the service account you have just created as bearer token.

After you have saved the form, open the `To App` sub tab. Make sure that the `Create Users`, `Update User Attributes` and `Deactivate Users` options are enabled. The `Sync Password` option must be disabled.

### Configure the groups to be pushed

**IMPORTANT** Use [a different group](https://help.okta.com/en-us/content/topics/users-groups-profiles/app-assignments-group-push.htm) for application assignment in Okta. The group used for application assignment cannot be pushed to Zentral.

To push an Okta group to Zentral, open the `Push Groups` tab of the Okta application. Click on the `Push Groups` dropdown, look for the group by name or rule, select it. There will probably be no match for the group in Zentral, so the `Create Group` option is displayed, with the named of the group that will be created in Zentral greyed out. You can save this mapping or save and add another one.
