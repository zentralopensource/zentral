# OneLogin - SAML integration

This is a quick guide to help integrate [OneLogin](https://www.onelogin.com/) with Zentral.

In Zentral, identity providers (IdP) are configured using realms. There are three kinds of realm: SAML, OIDC, and LDAP. In this case, we will use a SAML realm.

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

### Configure the group mappings

We need to map the `Default` and `Admin` OneLogin application roles to Zentral groups.

In Zentral, go to `Setup > Groups` and make sure you have two groups corresponding to the two roles in OneLogin. Set the permissions of each group in Zentral according to your requirements. You could of course add more roles in OneLogin and map them to more Zentral groups.

Go back to the realm detail view. For each role in OneLogin, we need to create a realm group mapping in Zentral:

|Zentral group mapping attribute|Value|
|---|---|
|Claim|roles|
|Separator|`;`|
|Value|name of the application role in OneLogin|
|Group|Zentral group|

### Test the realm

Use the `🕶️ Test` button in the Zentral realm detail view to test the mapping of the claims/parameters and roles/groups. It will redirect you to OneLogin and then display the OneLogin information sent to Zentral, and the mappings.
