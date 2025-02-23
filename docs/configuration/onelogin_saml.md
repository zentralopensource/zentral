# OneLogin - SAML Setup

We will start by setting up an OneLogin application. We will then configure a Zentral realm for this application. Finally, we will update the OneLogin application configuration, and configure the Zentral mappings.

## Create a OneLogin application

### SAML application

In OneLogin, from the `Administration > Applications` view, click on the `Add App` button.

Select the `SAML Custom Connector (Advanced)` type.

Pick a name and save the app.

In the `Info` view, click the `More Actions` button and download the metadata.

**IMPORTANT** those metadata are only temporary ones! Once the configuration is done, you will need to download a new version of the metadata.

### Roles

Go to the `Users > Roles` section. Make sure there are `Default` and `Admin` roles for the app you have just created, with the correct user mappings.

## Create the Zentral realm

In Zentral, go to `Setup > Realms`, click on `Create realm` and select `SAML realm`.

Fill up the form:

 - Pick a name
 - Select `Enabled for login` if you want to use this realm as login realm
 - Pick a login session expiry (can be left empty, see help text)
 - Use `username`, `email`, `first_name`, `last_name` for the claims
 - Leave `Full name claim` empty
 - Upload the metadata file that you have just saved (see [previous section](#create-a-onelogin-application))
 - If you want to allow logins initiated by the IDP, tick the box

## Update the OneLogin application

We will use the information displayed in the Zentral realm detail page to finish configuring the OneLogin app.

### Configuration

Set the following values in the `Configuration` tab of the OneLogin app:

|OneLogin attribute|Zentral realm value|
|---|---|
|RelayState|Default relay state<br><br>Only available if IdP initiated login is checked.<br>Make sure there are no whitespaces!|
|Audience (EntityID)|Entity ID|
|Recipient|Assertion Consumer Service URL|
|ACS (Consumer) URL|Assertion Consumer Service URL|
|SAML initiator|OneLogin|
|SAML nameID format|Email|
|SAML issuer type|Generic|
|SAML signature element|Assertion|

### Parameters

Set the following fields in the `Parameters` tab of the OneLogin app:

|SAML Custom Connector (Advanced) Field|Value|
|---|---|
|email|Email|
|first\_name|First Name|
|last\_name|Last Name|
|roles|User Roles|
|username|Email name part|

## Update and test the Zentral realm

### Update the realm metadata

**IMPORTANT** Download the OneLogin app metadata again! Click the `More Actions` button and save the file.

In Zentral, click on the `Update` button in the realm detail view, and upload the metadata file.

Check that everything works: click the 'Test' button (icon to the right of the realm name) on the Zentral Realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Role Base Access Control (RBAC)

See [Realm Group and Roles setup](../sso/#realm-groups) for more information.
