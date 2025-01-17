# Microsoft Entra ID - SAML Setup

We will start by setting up an Entra ID Enterprise Application with the Basic SAML Configuration. We will then configure a Zentral realm for this application. Finally, we will update the Entra ID application configuration.

## Create an Entra ID  application

Follow along with the Entra documentation available [here](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso).

### Create the app

Browse to Entra ID `Enterprise Applications`, select `Create your own application` and opt for `Non-gallery application`, set a name and click `Create`, this will take you to a newly created app. 

Select the `Single Sign-On` option in the tiles or in the menu to start the setup, select the `SAML` option for editing the configuration.

### Configure the SAML settings

#### General

⚠️ The Zentral URLs for the SAML integration are only available after the realm has been saved. In order to be able to save the realm, we need the metadata from the Entra ID Enterprise App. This is a chicken-egg kind of problem. That's why we suggest first use temporary dummy values for some of the `required` fields in Entra ID initially and update them later.

1. Set dummy values for the `Identifier (Entity ID)` and `Reply URL (Assertion Consumer Service URL)` required fields. Note that the URL must include `https://` even for dummy values. 
2.  Keep the default settings for the `Attributes & Claims` section.

#### Attribute Statements

Use the attribute mappings provided below when configuring the Zentral realm with Entra ID for SSO. 

| **Zentral realm - Attribute**    | **Claim name** | **Entra ID Value**      |
| ---------------- | ---------------------- | ---------------------- |
| Username claim   | name                   | user.userprincipalname |
| Email claim      | emailAddress           | user.mail              |
| First name claim | givenName              | user.givenname         |
| Last name claim  | surname                | user.surname           |

The default SAML claim mappings (see above) in Entra ID may not align with your organization's needs and could require adjustments.

### Download the Entra ID Enterprise App metadata

Download the `Federation Metadata XML` file from the `SAML Certificates` section.

## Create the Zentral realm

In Zentral, go to `Setup > Realms`, click on `Create realm` and select `SAML realm`.

Fill out the form:

 - Pick a name for the Realm config
 - Select `Enabled for login` if you want to use this realm as login realm
 - Pick a login session expiry (can be left empty, see help text)
 - Use the default claim mappings from the Entra ID SAML settings (see [section above](#attribute-statements)) for the claims
 - Leave `Full name claim` empty
 - Upload the metadata file you just saved (see [previous section](#download-the-entra-id-enterprise-app-metadata))
 - If you want to allow logins initiated by the IDP, tick the box

## Update the Entra ID application

We now have all the values required to finish configuring the Entra ID application.
In the Entra ID Enterprise app, update the SAML settings in the `Basic SAML Configuration` tab:

| **Entra ID application**     | **Zentral realm**                                                |
| --------------------------- | ---------------------------------------------------------------- |
| Identifier (Entity ID)      | Entity ID                                                        |
| Reply URL (Assertion Consumer Service URL)      | Assertion Consumer Service URL                                   |


You can check that everything is working by clicking the 'Test' button (icon to the right of the realm name) on the Zentral realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Role Base Access Control (RBAC)

See [Realm Group and Roles setup](/configuration/sso/#realm-groups) for more information.
