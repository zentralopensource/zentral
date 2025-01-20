# Google Workspace - SAML Setup

We will start by setting up a Google Workspace app for SAML-based SSO. We will then configure a Zentral realm for this application. Finally, we will update the Google Workspace application configuration.

### Create the app

In the Google Admin console, go to the menu `Apps > Web and mobile apps`, click `Add App > Add custom SAML app`.

In the next view, enter the app name, description ..., and click next.

### Download the Google Workspace IdP metadata

From the Google Identity Provider details download the `GoogleIDPMetadata.xml` file. 

### Configure the SAML settings

#### General

⚠️ The Zentral URLs for the SAML integration are known only once the realm has been saved, and in order to be able to save the realm, we need the metadata from Google Workspace. This is a chicken-egg kind of problem. That's why we have to first use dummy values for some of the fields, and update them later.

1. Set dummy values for `ACS URL`, `Entity ID` in the Service provider details.  
2. Do not check signed response.  
3. Stick to the defaults for Name ID as displayed, with Name ID format `UNSPECIFIED`, and Name ID set to `Basic Information > Primary email`

#### Attribute Statements

Use the attribute mappings provided below when configuring the Zentral realm with Google Workspace app for SAML-based SSO.

Add the following mappings:


| Google directory attributes | App attributes  |
| :---- | :---- |
| Primary Email | username |
| Primary Email | email |
| First Name | first\_name |
| Last Name | last\_name |




## Create the Zentral realm

In Zentral, go to `Setup > Realms`, click on `Create realm` and select `SAML realm`.

Fill up the form:

- Pick a name  
- Select `Enabled for login` if you want to use this realm as login realm  
- Pick a login session expiry (can be left empty, see help text)  
- Use `email`, `email`, `first_name`, `last_name` (see [section above](#attribute-statements)) for the claims  
- Leave `Full name claim` empty  
- Upload the metadata file that you have just saved (see above)  
- If you want to allow logins initiated by the IDP, tick the box

## Update the Google Workspace application


Now you have all the values to finish configuring the Google Workspace SAML application.

In the `General` tab of the app, update the SAML settings:

|Google Workspace SAML|Zentral realm|
|---|---|
|ACS URL|Assertion Consumer Service URL|
|Entity ID|Entity ID|
|Start URL|Default RelayState (only if realm setup for IdP initiated login)|

Set up `User access` to turn on the SAML app and select a group or organisational unit to make SAML login available to selected users.

Check that everything works: click the 'Test' button (icon to the right of the realm name) on the Zentral Realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Role Base Access Control (RBAC)

See [Realm Group and Roles setup](/configuration/sso/#realm-groups) for more information.
