# SSO Setup: Realms, Realm Groups & Roles 

## Realms

### Overview

Realms are authentication configurations that connect Zentral with an identity provider (IdP), to allow users access to different services in Zentral. Zentral supports SAML, OIDC, and LDAP, to provide Single Sign-On (SSO). Zentral also supports the System for Cross-Domain Identity Management (SCIM). With SCIM, changes at the IdP are immediately pushed to Zentral. 

The Realm configuration enables SSO authentication for:

* the Zentral Web Console administration  
* the User Portal   
* enrollment with Mobile Device Management and Automated Device Enrollment (ADE), Over-the-Air Enrollment (OTA), and Account Driven Enrollments

### Realm Users & IdP Claims

Your IdP provides user information to authenticate and log in to Zentral with SSO. In Zentral, IdP user attributes are called "Claims". IdP Claims are mapped to Realm User attributes. The Claims differ with IdPs and the IdP Claim for username could be something like “email”, “name” or “username”. You can also define custom attributes (e.g. “department”). Please refer to **[SSO Setup Guides](#sso-setup-guides)** for detailed instructions.

### Realm Setup

It is good practice to separate users that will have access to the Zentral Web Console from users that will only “consume” the services (enrollment in MDM, the User Portal). You would end up with end-users that could log in to Zentral otherwise, whether or not they have permissions to change or view any settings. To do this, you can, and should, configure multiple Realms: One for Zentral Administration, one for MDM Enrollment and the User Portal.

#### SAML Realms 

1. To create a SAML Realm in Zentral Select Realms from the platform settings menu in the top right corner  
2. Click the \+ icon to create a new Realm, select the type, e.g. SAML Realm and set a name  
3. Give Access:  
1) For Zentral admins, check “Enable for login”, and set “Login session expiry” (e.g. 3600\)  
2) For the MDM Enrollment, leave “enable for login” unchecked. Optional: check “User Portal”, if active   
4. Map the Claims from your IdP to the Username, Email, First name, Last name fields and any custom attributes  
5. If using, enable SCIM  
6. Pull a meta-data file from our IdP and upload it to Zentral (please refer to **[SSO Setup Guides](#sso-setup-guides)** for detailed instructions)  
7. Click save. You should see an overview of the Realm   
8. Update the SAML config with the IdP: Copy the values for “Entity ID” and “Assertion Consumer Service URL” (ACL) over to your IdP  
   

Check that everything works: click the 'Test' button (icon to the right of the realm name) on the Zentral Realm detail page. It will trigger an authentication with the IdP and display the claims Zentral receives with their mappings.

## Realm Groups

Realm Groups organize users into groups for managing access and permissions. There are two methods to achieve this:

1. User Claims → Realm Group mappings:  
   You can map IdP claims to Realm Groups in Zentral. For example, you could include your IdP group memberships in the Claims, and let Zentral look for a Value to map users that match the criteria to a Realm Group. Claims (and therefore Realm Group memberships) are updated when the user logs in:   
- If the IdP Claim matches, the user is added to the Realm Group.  
- If the IdP Claim does not match, the user is removed from the Realm Group.

2. SCIM:  
   Automates the synchronization of user attributes and group memberships from the IdP. Preferred method when available, because changes are pushed from the IdP. **Currently the SCIM functionality is only fully tested with Okta**.

Note: Do not mix Realm Group mappings and SCIM. Use one method based on your IdP's capabilities.

### Create a Realm Group

1. Select "Groups" from the platform settings menu in the top right corner.  
2. Click the \+ icon to create a new realm group.  
3. Pick the Realm that this group shall be assigned to and give it a Display name.  
4. Click Save

### Create a Realm Group mapping

1. Select "Groups" from the platform settings menu in the top right corner  
2. Click on the Group Name you want to create a mapping for  
3. Click the \+ icon in the Group mappings section to create a new Realm Group Mapping  
4. Fill in the fields with a Claim and Value that match with the configuration of your IdP. Note: the Separator can usually be left blank  
5. Select the target Realm Group from the drop-down  
6. Click Save

## Roles

Roles define what actions users can perform and what resources they can access within Zentral. You can map sets of permissions to roles in Zentral for Role-Based Access Control.  
 

* A Role like "Editors" might have permissions to add, change, delete and view items in the Zentral console  
* A Role like "Viewers" might only have view permissions for the same items and settings

A Role mapping assigns a Role to a Realm Group. Members of a Realm Group, inherit the permissions defined in the Role mapped to that Realm Group. Zentral evaluates Role mappings when Realm Group memberships change.

### Create a Role 

1. Select "Roles" from the platform settings menu in the top right corner  
2. Click the \+ icon to create a new Role and give it a name  
3. Assign permissions to this role from the list. Use command+click to multi-select or select all and use command+click to deselect.  
4. Click Save

### Create a Role Mapping

1. Select "Groups" from the menu in the top right corner   
2. Click on the Group’s Name you want to map the Role to  
3. Click the \+ icon to create a new Role mapping  
4. Select the Realm Group and select the Role  
5. Click Save

## SSO Setup Guides

 * [Entra ID](../entra_id_saml/)
 * [Google Workspace](../google_saml/)
 * [Okta SAML](../okta_saml/)
 * [Okta SCIM](../okta_scim/)
 * [One Login](../onelogin_saml/)
