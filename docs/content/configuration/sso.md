---
title: SSO Setup
weight: 110
---

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

Only a superuser logged in without a Realm can create or change a Realm.

A superuser cannot log in with a Realm: through a Realm, the IdP would control the superuser account. A superuser logs in with a password. A Realm login that finds a superuser fails, and a Realm session stops when its user becomes a superuser. A user that a Realm login made has no password, so it cannot be a superuser.

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

### SCIM and Zentral users

When the Realm is enabled for login, SCIM also updates the Zentral user that has the email or the username of the Realm User. What SCIM writes depends on the Zentral user:

| Zentral user | Username and email | First name and last name | Deactivate | Activate again |
|---|---|---|---|---|
| Remote user | Yes | Yes | Yes | Yes |
| Local user | No | Yes | Yes | No |
| Superuser | No | No | No | No |

* If another Zentral user has the new username or email of a remote user, SCIM refuses the write with a 409 error. If the write also deactivates the remote user, SCIM deactivates it and keeps the old username or email, on the Zentral user and on the Realm User.
* SCIM does not write an empty username or email on a remote user.
* The username and the email of a local user are credentials, and an activation would make the password of the user work again. Only an operator can activate a local user again.
* A deactivated user cannot log in, and loses all access immediately.

To offboard a superuser:

1. If the user is the last superuser, make a new superuser.
2. As another superuser, remove the superuser flag of the user.
3. Delete the user. The IdP does not send the deactivation again after you remove the flag, so do not wait for SCIM.

If you can view the Realm Users, these pages show their SCIM status:

| Page | What it shows |
|---|---|
| Users list | For each user, the Realm Users that have its email or its username, on the Realms enabled for login, with "SCIM inactive" next to a Realm User that SCIM deactivated. Use it to find a superuser that the IdP deactivated. |
| User page | The same Realm Users, with "SCIM active?" and "Last SCIM update". |
| Realm User page | "SCIM active?" and "Last SCIM update". |

"Last SCIM update" is "-" if SCIM never wrote the Realm User. The IdP does not always send a user again when nothing changes, so an old time does not always mean that SCIM stopped.

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

Each change in the console of a Realm Group, of its members, of a Realm Group mapping or of a Role mapping emits a `zentral_audit` event. The event of a Role mapping links to the Realm Group and to the Role.

You can delete a Realm Group in the console only when it has no Realm Group mapping, no Role mapping and no child group. Delete the mappings first, on their own pages: each deletion emits its own event. A child group gets its parent from SCIM, so change it in the IdP. The deletion of a Realm Group does not emit an event for each of its members.

## Roles

Roles are named labels that group users and service accounts. A Role on its own grants no access — you authorize it by writing a [PBAC policy](pbac.md) that references it.

* A Role like "Editors" might be the principal of a policy granting every admin action across the inventory and MDM apps.
* A Role like "Viewers" might be the principal of a policy granting every view action across all apps.

A Role mapping assigns a Role to a Realm Group. Members of a Realm Group inherit the Role mapped to that Realm Group — and through that Role, any PBAC policies targeting it. Zentral evaluates Role mappings when Realm Group memberships change.

### Create a Role

1. Select "Roles" from the platform settings menu in the top right corner.
2. Click the \+ icon to create a new Role and give it a name.
3. Click Save.

The Role is now an empty label. To grant it access, see [Writing a policy](pbac.md#writing-a-policy).

### Create a Role Mapping

1. Select "Groups" from the menu in the top right corner.
2. Click on the Group's Name you want to map the Role to.
3. Click the \+ icon to create a new Role mapping.
4. Select the Realm Group and select the Role.
5. Click Save.

### Who can give a Role

In the console, only a superuser, logged in without a Realm, gives or removes a Role: on the form of a User or a Service Account, with a Role mapping, with a Realm Group mapping, or with the members of a Realm Group. A superuser also creates, changes and deletes the Realm Groups, the mappings and the Roles.

Holding a Role is not holding its access. A `forbid` on a Role, a policy that names an account, or a policy on the type of the account all change what a Role gives, so a comparison of the Roles of two users does not bound what one can give to the other. Until Zentral has a delegated administration, a superuser makes these changes. A superuser cannot log in with a Realm. The IdP controls the memberships that SCIM and the Realm Group mappings write.

## SSO Setup Guides

 * [Entra ID](entra_id_saml.md)
 * [Google Workspace](google_saml.md)
 * [Okta SAML](okta_saml.md)
 * [Okta SCIM](okta_scim.md)
 * [One Login](onelogin_saml.md)
