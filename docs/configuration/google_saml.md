# Google Workspace - SAML Setup

We will start by setting up a Google Workspace app for SAML-based SSO. We will then configure a Zentral realm for this application. Finally, we will update the Google Workspace application configuration.

## Create a Google Workspace custom SAML app

In the Google Admin console, go to the menu `Apps > Web and mobile apps`, click `Add App > Add custom SAML app`.

In the next view, enter the app name, description ..., and click “Continue”.

### Download the Google Workspace IdP metadata

Select Option 1: download the IdP metadata file and save it for later use. Click “Continue”.

### Configure the Service provider details

⚠️ You will only know the Zentral URLs for the SAML integration once the realm has been saved. To save the realm, you need the metadata from Google Workspace. This is a chicken-egg problem. We have to use dummy values for the fields first, and update them later.

1. Set dummy values for `ACS URL`, `Entity ID` in the Service provider details (eg. https://1.2.3.4).
2. Do not check signed response.
3. Stick to the defaults for Name ID as displayed, with Name ID format `UNSPECIFIED`, and Name ID set to `Basic Information > Primary email.`
4. Click “Continue”.

### Configure the Attributes

Add the Attributes mappings below:

| Google directory attributes | App attributes  |
| :---- | :---- |
| Primary Email | **email** |
| First Name | **first\_name** |
| Last Name | **last\_name** |

Click “Finish”.

## Create the Zentral realm

1. In Zentral, go to `Platform settings > Realms (top right corner)`
2. Click on the `+` icon to create a new Realm, select SAML Realm and set a name.
3. Give Access:
    * For Zentral admins, check “Enable for login”, and set “Login session expiry” (e.g. 3600)
    * For the MDM Enrollment, leave “enable for login” unchecked. Optional: check “User Portal”, if active
4. Use `email` (for the username), `email`, `first_name`, `last_name` (see [section above](#configure-the-attributes)) for the claims
5. Leave `Full name claim` empty
6. Upload the metadata file that you have just saved (see above)
7. If you want to allow logins initiated by the IDP, tick the box
8. Click save. You should see an overview of the Realm.
9. ⚠️ Note the details for `Assertion Consumer Service URL` and  `Entity ID`.

## Update the Google Workspace custom SAML app

Return to the custom SAML app view in the Google Admin console. In the `Service provider details` block, update the SAML settings and save them.

| Google Workspace SAML | Zentral realm |
| :---- | :---- |
| ACS URL | Assertion Consumer Service URL |
| Entity ID | Entity ID |
| Start URL | Default RelayState (only if realm setup for IdP initiated login) |

⚠️ 	In the `User access` view, make sure `service status` is “ON for everyone” for the required Organizational Units. For more information about this, refer to the [Google docs](https://support.google.com/a/answer/6087519?hl=en#zippy=%2Cstep-turn-on-your-saml-app).

Check that everything works: click the 'Test' button (icon to the right of the realm name) on the Zentral Realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Role Base Access Control (RBAC)

See [Realm Group and Roles setup](../sso/#realm-groups) for more information.
