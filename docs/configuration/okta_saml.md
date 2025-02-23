# Okta - SAML Setup

We will start by setting up an Okta application. We will then configure a Zentral realm for this application. Finally, we will update the Okta application configuration.

## Create an Okta application

### Create the app

In Okta, from the `Applications` view, click on the `Create App Integration` button, then select `SAML 2.0`.

In the next view, pick an app name, a logo, …

### Configure the SAML settings

#### General

⚠️ You will only know the Zentral URLs for the SAML integration once the realm has been saved. To save the realm, you need the metadata from Okta. This is a chicken-egg problem. We have to use dummy values for the fields first, and update them later.

1. Set dummy values for `Single sign on URL`, `Audience URI (SP Entity ID)`, and `Default RelayState`
2. Set `Application username` to `Okta username`
3. Set `Update application username` on `Create and update`

#### Attribute Statements

Add the following mappings:

|Name|Name Format|Value|
|---|---|---|
|username|Unspecified|user.login|
|email|Unspecified|user.email|
|first\_name|Unspecified|user.firstName|
|last\_name|Unspecified|user.lastName|

### Download the Okta app IdP metadata

In the `Sign On` tab of the Okta application, click on the `View SAML setup instruction` button.

At the bottom of the page, copy the IdP metadata and save it to a file.

## Create the Zentral realm

In Zentral, go to `Setup > Realms`, click on `Create realm` and select `SAML realm`.

Fill up the form:

 - Pick a name
 - Select `Enabled for login` if you want to use this realm as login realm
 - Pick a login session expiry (can be left empty, see help text)
 - Use `username`, `email`, `first_name`, `last_name` (see [section above](#attribute-statements)) for the claims
 - Leave `Full name claim` empty
 - Upload the metadata file that you have just saved (see [previous section](#download-the-okta-app-idp-metadata))
 - If you want to allow logins initiated by the IDP, tick the box

## Update the Okta application

We now have all the values required to finish configuring the Okta application.

In the `General` tab of the app, update the SAML settings:

|Okta application|Zentral realm|
|---|---|
|Single sign on URL|Assertion Consumer Service URL|
|Audience URI (SP Entity ID)|Entity ID|
|Default RelayState|Default RelayState (only if realm setup for IdP initiated login)|

Check that everything works: click the 'Test' button (icon to the right of the realm name) on the Zentral Realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Role Base Access Control (RBAC)

See [Realm Group and Roles setup](/docs/configuration/sso.md#realm-groups) for more information.
