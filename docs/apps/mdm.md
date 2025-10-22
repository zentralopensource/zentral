# MDM

Zentral can be used as MDM server for Apple devices.

## Zentral configuration

To activate the MDM module, you need to add a `zentral.contrib.mdm` section to the `apps` section in `base.json`.

### SCEP CA issuer chain

To authenticate the OTA enrollments, Zentral needs the SCEP CA issuer certificate chain in PEM form in the `scep_ca_fullchain` key of the `zentral.contrib.mdm` section. It is possible to use the `{{ file:PATH_TO_PEM_CHAIN }}` substitution to load the chain from a file on disk.

### mTLS proxy

Zentral is expecting the client certificate in PEM form in the `X-SSL-Client-Cert` header, and the client certificate subject DN in the `X-SSL-Client-S-DN` header. If this is not possible, you can set `mtls_proxy` to `false` in the `zentral.contrib.mdm` section. In that case, the Apple devices will be configured to add a header containing the payload signature in each HTTP request. See the [Apple documentation](https://developer.apple.com/documentation/devicemanagement/implementing_device_management/managing_certificates_for_mdm_servers_and_devices#3677960). This adds approximately 2KB of data to each message.

## Variable substitution

It is possible to use variable substitution to customize [configuration profiles](https://developer.apple.com/documentation/devicemanagement/configuring_multiple_devices_using_profiles) and application configurations (see [InstallApplication](https://developer.apple.com/documentation/devicemanagement/installapplicationcommand/command/configuration) and [InstallEnterpriseApplication](https://developer.apple.com/documentation/devicemanagement/installenterpriseapplicationcommand/command/configuration) MDM commands) with device or user attributes. The following variables are available:

|Name|Description|
|---|---|
|`$ENROLLED_DEVICE.UDID`|UDID of the enrolled device|
|`$ENROLLED_DEVICE.SERIAL_NUMBER`|Serial number of the enrolled device|
|`$ENROLLED_USER.LONG_NAME`|Long name of the user reported by the MDM|
|`$ENROLLED_USER.SHORT_NAME`|Short name of the user reported by the MDM|
|`$REALM_USER.USERNAME`|Username of the realm user|
|`$REALM_USER.DEVICE_USERNAME`|Device username (first part of the username split on `@`, with `.` removed) of the realm user|
|`$REALM_USER.EMAIL_PREFIX`|first part of the email split on `@` of the realm user|
|`$REALM_USER.EMAIL`|email of the realm user|
|`$REALM_USER.FIRST_NAME`|first name of the realm user|
|`$REALM_USER.LAST_NAME`|last name of the realm user|
|`$REALM_USER.FULL_NAME`|full name of the realm user|
|`$REALM_USER.CUSTOM_ATTR_1`|first custom attribute of the realm user|
|`$REALM_USER.CUSTOM_ATTR_2`|second custom attribute of the realm user|

NB: the realm user variables are only available when a realm authentication is configured in the enrollment.

## Push certificates

To be able to send notifications to the devices, Zentral requires a push certificate (also known as an APNS certificate). You have two options to obtain this:

* Use our signed Certificate Signing Request (CSR): Since Zentral is an approved vendor, you can directly use our provided signed CSR in Zentral Cloud (SaaS) instances.

* Generate your own MDM vendor certificate: An Apple [Developer Enterprise Account](https://developer.apple.com/programs/enterprise/) with the ability to generate MDM CSRs is required. You can then use this vendor certificate to sign an APNS certificate request. The `mdmcerts` Zentral management command can be used to help with this process.


### Configure Apple Push Notification Service (APNS)

To configure the Apple Push Notification Service (APNS) for Zentral Cloud, follow these steps. 

* From the sidebar or three-line menu in the top-right corner, navigate to the Zentral *MDM > Overview > Push certificates* section.
* Click the `Zentral Cloud` link under the Name column to go to the certificate detail page.
* In the top right corner, click the 'down-arrow' button to download a signed CSR `push_certificate_1_signed_csr.b64` file.
* Sign in to the [Apple Push Certificate Portal](https://identity.apple.com).
* On the "Get Started" page, click the "Create a Certificate" green shiny button
* Click the checkbox to the left of the "I have read and agree to these terms and conditions." text and click the Accept button
* On the "Create a Push Certificate" page, optionally enter a note, click the "Choose File" button and navigate to the `push_certificate_1_signed_csr.b64` signed certificate request file, and then click the "Upload" button.
* On the "Confirmation" page, click the "Download" button.
* Return to the Zentral *MDM > Overview > Push certificates > Zentral Cloud* certificate detail page. 
* From the top right corner, click the "Upload Push Certificate" "up-arrow" button to go to the upload page
* Click the "Choose File" button and navigate to the "MDM_ Zentral Pro Services GmbH & Co. KG_Certificate.pem" certificate and click the Open button in the filepicker.
• Click the green Save button.

As you can now see the certificate details filled in above, this configuration is now ready for Zentral MDM push capabilities. To renew an existing push certificate, repeat those steps. 

**IMPORTANT** do not let the push/APNS certificates expire! Set a reminder and renew it before the "Not after" date listed, or at a regular interval more frequent than the lifetime of the certificate.

To be able to keep sending notifications to enrolled devices, it is important to renew the existing certificates, and not generate new ones (it is important that the *topic* of a push certificate stays the same). In the [Apple Push Certificate Portal](https://identity.apple.com), look for the existing certificate and click on the `Renew` button, and not on the `Create a Certificate` button.

### MDM vendor certificate (Developer Enterprise Account required)
To generate your own MDM vendor certificate, run the following command to setup a working directory with a vendor certificate request:

```bash
python server/manage.py mdmcerts -d the_working_directory init
```

* Choose a password for the vendor certificate request private key, and remember it!

The content of the working directory should be the following:
```bash
$ ls the_working_directory
vendor.csr  vendor.key
```

 * Sign in to the [Apple Developer Portal](https://developer.apple.com/account) and navigate to [Certificates, Identifiers & Profiles](https://developer.apple.com/account/resources/certificates/list).
 * Create a new certificate, choose *Services > MDM CSR*.
 * Upload the `vendor.csr` file.
 * Download the generated certificate and store it as `vendor.crt` in the working directory.

### Push/APNS certificate

Run the following command to create an APNS certificate request and sign it with the vendor certificate:

```bash
python server/manage.py mdmcerts -d the_working_directory req COUNTRYCODE
```

 * Choose a password for the push/APNS certificate request private key, and remember it!
 * Enter the password for the MDM vendor certificate private key.

The content of the working directory should be the following:
```bash
$ ls the_working_directory
push.b64  push.csr  push.key  vendor.crt  vendor.csr  vendor.key
```

 * Sign in to the [Apple Push Certificate Portal](https://identity.apple.com).
 * To renew an existing certificate, choose the certificate and click the *Renew* button.
 * To create a new certificate, click the *Create a Certificate* button.
 * Upload the `push.b64` signed certificate request.
 * Download the generated certificate.

Navigate to the Zentral *MDM > Push certificates* section, and either select an existing certificate and click on the *Update* button to renew an existing certificate, or click on the *Add* button to create a new push certificate. Upload the generated certificate, the `push.key` private key, and enter the password of the push certificate private key.

### Renewing a Push/APNS certificate

**IMPORTANT** do not let the push/APNS certificates expire! Set a reminder and renew it before the "Not after" date listed in the column, or at a regular interval more frequent than the lifetime of the certificate.

To be able to keep sending notifications to enrolled devices, it is important to renew the existing certificates, and not generate new ones (it is important that the *topic* of a push certificate stays the same). In the [Apple Push Certificate Portal](https://identity.apple.com), look for the existing certificate and click on the `Renew` button, and not on the `Create a Certificate` button. In the Zentral *MDM > Push certificates* section, find the certificate and click on the *Update* button, and do not *Add* a new certificate.

## Automated Device Enrollment

To use modern automated device enrollment with Zentral, you need to ensure proper synchronization with Apple Business Manager (ABM) or Apple School Manager (ASM). This synchronization requires an MDM server token.

### Prerequisites

- Access to Apple Business Manager (ABM) or Apple School Manager (ASM).
- An MDM server token for syncing with ABM/ASM.

For detailed instructions on general ABM/ASM usage, refer to the [Apple Business Manager User Guide](https://support.apple.com/en-ca/guide/apple-business-manager/welcome/web).


### Configure Automated Device Enrollment (formerly known as DEP)

To set up Automated Device Enrollment (ADE) to work with Zentral, follow these steps:

* Navigate to the Zentral *MDM > Overview > DEP Virtual Servers* section and click the *Connect* "power-plug" button in the top right. Do not close this section during the process.
* Next to the text that says "Download the new public key", click the "down-arrow", "Download public key" button.
* Log into your ABM/ASM account and select *Preferences* under your user in the bottom-left corner (assuming your user has the appropriate permissions) and look for the *Device Management Services* section in the middle column, under "API".
* Add a new MDM Server by clicking the "plus-circle" with 'Add' below it at the top of that section, setting a Service Name as you'd prefer. (You may also choose, now or after the entry has been created, to allow Zentral to release devices on your behalf, in which case you'd click that associated radio button as well.)
* Upload the <your_zentral_domain_name>.zentral.cloud_public_key_<number>_<datetimestamp>.pem public key as directed in the 'well' section on the right pane, and click the Save button.
* Once the page refreshes, click the `Download Token` button at the top of the right-pane window. A warning will appear indicating this would reset any pre-existing token, but as this the first time you're interacting with this entry it's safe to confirm by clicking the Download Token button. 
* Return to Zentral and click the "Choose File" button to upload the MDM server token in the *MDM > Overview > DEP Virtual Servers* section.
* Once an *Enrollment* profile has been created (see the section below), you can assign it as the default enrollment for this token.

To fully utilize ADE, you need to create an *Enrollment* in the *MDM > Overview > Enrollment* section and select the appropriate *Virtual Server* during the setup process (see below). The assigned *Enrollment* will be reflected in the *MDM > DEP Virtual Servers > [Instance Name] > Profile* section, and the devices assigned in ABM/ASM will appear in the *MDM > DEP Virtual Servers > [Instance Name] > Devices* section. You cannot re-use an enrollment that is set as the default for an existing DEP Virtual Server, but the same blueprint can be used for multiple enrollments.

Devices can be assigned from Apple's side to a management service like Zentral via the [ABM](https://support.apple.com/guide/apple-business-manager/create-an-api-account-axm33189f66a/1/web/1) or [ASM](https://support.apple.com/guide/apple-school-manager/create-an-api-account-axm33189f66a/1/web/1) API. For device assignments in ABM/ASM to be reflected in Zentral, go to the *MDM > DEP Virtual Servers > [Instance Name]* section and click the `Synchronize` button. The devices will also be visible in the *MDM > Overview > DEP Devices* section. Syncronizations can be triggered per DEP Virtual Server over the Zentral API as well.

### Setup an Enrollment Profile

To set up an Automated Device Enrollment (ADE) in Zentral, you need to create an *Enrollment*. Follow these steps:

* Navigate to the Zentral *MDM > Enrollment* section.
* Check if there is an existing enrollment entry under *DEP Enrollment*. If none exists, click the *Add* button to create a new enrollment profile.
* Fill in or update the required details. Select **Push Certificate**, **SCEP Config**, **Blueprint**, and choose the appropriate *Virtual Server* from the dropdown menu to associate this enrollment with a DEP Virtual Server. Set a **Name** to identify the profile.
* Configure device management options according to your organization’s needs. This includes settings like **Allow Pairing**, **Is Supervised**, and **Is MDM Removable**.
* Enter additional settings, such as **Support Phone Number**, **Support Email Address**, **Language**, and **Region** to provide users with the necessary contact and localization details.
* If applicable, configure user and realm-specific settings. These include **Realm**, **Use Realm User**, **Username Pattern**, and whether the **Realm User is Admin**.
* Review and customize the Setup Assistant settings, choosing which steps to skip during device setup, such as **Skip Apple ID Setup**, **Skip Touch ID/Face ID Setup**, and **Skip iCloud Setup**.
* Once all settings are configured, click *Save* to create the enrollment profile.


**Note:** After creating the *Enrollment*, it’s important to test and review the profile settings. You can edit the enrollment profile anytime by navigating to the *MDM > Enrollment* section in Zentral. Regular testing and revisit for updates are recommended, especially as new major OS versions can introduce additional configurations. To verify that your changes are synced with ABM/ADE, use the *Test* button to download and check the DEP profile from ABM.

Device syncing occurs at scheduled intervals. If the device assignments from ABM/ASM are not reflected in Zentral, go to the *MDM > DEP Virtual Servers > [Instance Name]* section and manually click the `Synchronize` button.

## MDM Blueprints

Blueprints in Zentral are templates that group MDM settings and configurations. They determine which profiles, settings, and apps are applied to managed devices, enabling consistent and standardized management through simple assignment.

### How MDM Blueprints Work 

Blueprints include essential settings for inventory collection and its interval, as well as configurations for `FileVault`, `Recovery password`, which are applied in a 1:1 relationship. For `Software Update Enforcement` one or more configurations can be used within a Blueprint, and by applying tags in a multiple-configuration scenario, different enforcement levels can be scoped to tagged device cohorts, enabling fine-grained update strategies across device groups.

These configurations are typically applied by assigning a dedicated blueprint during enrollment, and can be adjusted later if needed.

- **Single assignment**: A device can only be assigned to one blueprint at a time to prevent conflicts.
- **Default enrollment**: Blueprints are typically set initially as the default assignment during Automated Device Enrollment (ADE) when devices are enrolled via Apple Business Manager (ABM) for automatic application of settings. The blueprint can be changed as needed.
- **Transitioning**: When a device is switched from one blueprint to another, the new blueprint’s configurations are applied, and any previous settings not included are removed.
- **Inventory collection**: Inventory data is collected at specified intervals, managed through the MDM protocol. The information is stored and updated as part of a device’s inventory records. The interval can range from a minimum of 4 hours to a maximum of 7 days, with a default of 1 day.

- **Artifacts**: Configuration profiles, Enterprise Apps, and VPP Apps are considered artifacts. When assigned to a Blueprint, they are listed with details such as type, version, platforms, exclusion tags, default shard, and tag shards. Clicking on an artifact allows you to view and edit its details.

- **Enrollment info**: Displays the connected Automated Device Enrollment (DEP) or Over-The-Air (OTA) enrollment configurations. You can click the link to view detailed enrollment information.

### Create a Blueprint

1. Go to *MDM > Overview > Blueprints* in the Zentral interface.
2. Click the *Add* button to create a new blueprint.
3. Enter a *Name* for the blueprint.
4. Set an *Inventory Interval* to determine the frequency of inventory collection.
5. Configure data collection options:
   - *Collect apps*: Select *Yes* or *No*.
   - *Collect certificates*: Select *Yes* or *No*.
   - *Collect profiles*: Select *Yes* or *No*.
6. Click *Save* to create the blueprint.

### Modify a Blueprint

1. Go to *MDM > Overview > Blueprints* and select the blueprint you want to modify.
2. Update fields such as *Name*, *Inventory Interval*, or data collection options as needed.
3. Click *Save* to apply the changes.

### Connect a Blueprint to an Enrollment

1. Go to *MDM > Overview > Enrollments* and select or create an enrollment profile.
2. In the *Blueprint* dropdown menu, select the blueprint you want to link.
3. Click *Save* on the enrollment profile to complete the connection.

For more details on configuring Automated Device Enrollment (ADE), refer to the [Setup an Enrollment Profile](#setup-an-enrollment-profile) section.

## FileVault Configuration

Zentral manages FileVault settings for full disk encryption on macOS devices via MDM. Using a dedicated configuration, it allows the creation and assignment of an individual FileVault configuration to one or more MDM Blueprints. This approach provides centralized control over FileVault application, user experience, and key management, ensuring compliance with the organization’s data encryption policies.

Enforcing FileVault during the Setup Assistant is supported starting from macOS 14.4 and later.

### FileVault Key Escrow

FileVault key escrow ensures that Personal Recovery Keys (PRKs) are securely stored and accessible:

- **Escrow**: Zentral automatically escrows the PRK when FileVault is enabled and enforced via MDM on a device. Zentral deploys a device-specific certificate to encrypt the PRK, ensuring a secure procedure.
- **Authorized Retrieval**: The PRK can be accessed via the Zentral web interface or HTTP API for device recovery. Each retrieval action is audited in the *FileVault PRK Viewed* log, captured per device and transaction.

### Configure FileVault Configuration

To set up a FileVault configuration in Zentral, follow these steps:

1. Navigate to *MDM > Overview > FileVault Configuration*.
2. Configure the following options:
   - *Name*: Enter a display name for the configuration.
   - *PRK Escrow Location Display Name*: Information shown to the end-user indicating where the PRK is stored.
   - *Defer Enablement at Login Only*: Enable FileVault only during login to avoid prompts at logout.
   - *Max Bypass Attempts at Login*: Set the number of times users can bypass FileVault enablement at login.
   - *Show Recovery Key*: Choose whether to display the PRK to users when FileVault is enabled.
   - *Destroy Key on Standby*: Enable this to require a FileVault unlock after hibernation.
   - *PRK Rotation Interval (days)*: Specify an interval for automatic PRK rotation and escrow to Zentral. A value of 0 means no rotation.
3. Click *Save* to apply the configuration.

### Using FileVault Configuration Across Blueprints

A single FileVault configuration can be assigned to multiple blueprints, ensuring consistent encryption settings across various device groups.

### Linking a FileVault Configuration to a Blueprint

1. Navigate to *MDM > Overview > Blueprints*.
2. Select or create a blueprint.
3. Choose the desired FileVault configuration from the *FileVault Configuration* dropdown.
4. Click *Save* to link the configuration to the blueprint.

## Apps and Books

To manage and distribute apps from the Mac App Store or iOS/iPadOS App Store through Zentral, a Content Token is required to sync with Apple Business Manager (ABM) or Apple School Manager (ASM).

### Prerequisites

- Access to Apple Business Manager (ABM) or Apple School Manager (ASM).
- A Content Token for syncing with ABM/ASM.

For detailed instructions on general ABM/ASM usage, refer to the [Apple Business Manager User Guide](https://support.apple.com/en-ca/guide/apple-business-manager/welcome/web).


### Configure Apps and Books (formerly Apple Volume Purchasing/VPP)

To set up *Apps and Books* to work with Zentral, follow these steps:

* Navigate to the *ABM / ASM Preferences > Payments and Billing > Apps and Books* section.
* In the Content Tokens section, locate the desired token and download it.
* Navigate to the Zentral *MDM > Overview > Locations* section.
* Click the `Add` button to create a new location.
* Upload the content token (*.vpptoken) you previously downloaded from ASM/ABM.

Content in ASM/ABM *Apps and Books > "AppName" > Manage Licenses* that is assigned or removed from the content token will sync and automatically populate. You will see the total apps and licenses available reflected in Zentral Cloud in the *MDM > Overview > Store apps* section.

## Software Update Enforcement Configuration

Zentral uses Declarative Device Management (DDM) to configure policies for enforcing software updates across Apple platforms (macOS, iOS, iPadOS, tvOS). These policies ensure that devices update to a specific OS version by a defined target date and time, while allowing users to install the update at a time convenient for them (prior to the enforcement date). 

The configuration allows an optional *Details URL* setting, which is displayed in update messages on the device. This can provide a link to additional information (e.g., internal or public documentation) for end users.

Zentral offers two variants for setting up a Software Update Enforcement configuration:

- **One-Time**

    This type is standard DDM to specify the **Target OS version** (e.g.,`15.2`), optionally the **Target build version** (e.g., `24C101`), and a **Target local date and time** (e.g., `2024-12-17 09:30:00`) as a single policy to enforce the update. When new OS versions become available that need to be enforced, this configuration requires manual updates.


- **Latest**

  This type automatically enforces the latest available OS version up to a **Maximum target OS version**. Zentral will use the *device identifier* and match information from the *Apple Software Lookup Service* to return the latest OS version (e.g., `16` to install all macOS 15 updates on your fleet, but to stop before installing 16). Set the **Delay in days** following the software release and a **Target local time** to configure the enforcement time (e.g.`7` for 7 days and `09:30:00` for 9:30 a.m.).
  
In both types, if a user does not install the update by the specified deadline, it is automatically enforced. Enforcement times are based on the device's local time zone, allowing a single configuration to work seamlessly across different regions.

To read more about Apple's logic for enforcing software updates, refer to the [Apple Platform Deployment Guide](https://support.apple.com/en-gb/guide/deployment/depd30715cbb/1/web/1.0).


### Configuring Software Update Enforcement

To create and manage software update enforcement settings in Zentral, follow these steps:

1. Navigate to *MDM > Overview > Software Update Enforcements*.
2. Click *the + sign to create new software update enforcement*
3. Complete the following options:
   - *Name*: Enter a display name for the configuration.
   - *Details URL*: (Optional) A URL link, to provide info for end users.
   - *Platforms*: Select the platforms to which the enforcement applies (iOS, iPadOS, macOS, tvOS).
   - *Tags*: Add tags to specify which devices or groups the configuration will apply to.
   - *Type*: Choose the direction of how the enforcement schedule is set (as outlined above): 
        - **One-Time**: Set the *Target OS version*, *Target build version* (optional), and *Target local date and time*.
        - **Latest**: Set the *Maximum target OS version*, *Delay in days*, and *Target local time*.
4. Click *Save* to store the configuration.

### Linking a Software Update Enforcements Configuration to a Blueprint

1. Navigate to *MDM > Overview > Blueprints*.
2. Select or create a Blueprint.
3. Select the desired Software Update Enforcements configuration from the *Software Update Enforcements* list.
4. Click *Save* to link the configuration(s) to the Blueprint.

### Enforcing Updates on Different Schedules

Multiple configurations for enforcing software updates can be used within a single blueprint, each targeting specific device groups based on tags. This setup enables gradual rollouts with enforcement based on predefined schedules for different groups of tagged devices. When combined with *Latest Mode*, this approach eliminates the need for manual adjustments with each Apple OS release while maintaining the predefined schedules.

### Using a Software Update Enforcement configuration in multiple Blueprints

A single Software Update Enforcement configuration can be assigned to multiple blueprints, ensuring a consistent enforcement schedule and user experience across the devices and Apple platforms (macOS, iOS, iPadOS, tvOS).

### Update a Software Update Enforcement Configuration

To update an existing configuration:

1. Navigate to *MDM > Overview > Software Update Enforcements*.
2. In the list of configurations, click the *Edit button* right hand to the software update enforcement you want to modify.
3. Make the necessary adjustments as described in the configuration steps above.
4. Click *Save* to store the updated configuration.

### Removing a Software Update Enforcement Configuration

A Software Update Enforcement configuration can only be deleted if it is no longer linked to any blueprint. If the delete button is not visible, check the associated blueprints to ensure the configuration is no longer in use.

1. Navigate to *MDM > Overview > Software Update Enforcements*.
2. Click the configuration name to review its settings before deleting and use the *Delete button* next to the configuration. Alternatively, you see a delete button already in the list right to the name.

## Recovery Password Configuration

Recovery Password Configuration manages both **recoveryOS password protection** for Apple Silicon Macs and **firmware password protection** for Intel-based Macs via MDM. This prevents unauthorized access when Macs are started in recovery mode.

There are two types of passwords, static passwords, which set the same password for all devices, and dynamic passwords, which generate unique passwords for each device. A password rotation can be set only for dynamic passwords, the password rotation interval can be set in days (a value of `0` disables rotation). For Intel-based Macs, there is an extra checkbox to enable firmware password rotation, as Zentral needs to send a reboot command via MDM to apply the new password.

### Configuring a Recovery Password

1. Navigate to *MDM > Recovery Password Configurations*.  
2. Click the *Add* button to create a new configuration.  
3. Complete the following options:  
   - **Name**: Enter a display name for the configuration.  
   - **Dynamic Password**: Enable to generate unique passwords for each device.  
   - **Static Password**: Provide a static password for all devices *(only available when Dynamic Password is disabled)*.  
   - **Rotation Interval (days)**: Set the interval for automatic password rotation. Enter `0` to disable rotation.  
   - **Rotate Firmware Password**: Enable firmware password rotation *(only for Intel-based Macs; a reboot is required to apply the new password)*.  
4. Click *Save* to apply the configuration.  

### Linking a Recovery Password Configuration to a Blueprint

1. Navigate to *MDM > Overview > Blueprints*.
2. Select or create a Blueprint to edit.
3. Add the recovery password configuration to the blueprint.
4. Click *Save* to link the configuration to the Blueprint.

A recovery password configuration can be applied to multiple blueprints.

### Update a Recovery Password Configuration

To update an existing configuration:

1. Navigate to *MDM > Overview > Recovery Password Configurations*.  
2. Locate the desired configuration and click the *Edit* button next to it.  
3. Adjust the settings as needed (refer to the configuration steps for guidance).  
4. Click *Save* to apply the changes.  

### Remove a Recovery Password Configuration

A Recovery Password Configuration can only be deleted if it is not linked to any Blueprint. If the *Delete* button is unavailable, check associated Blueprints and ensure the configuration is no longer in use.

1. Navigate to *MDM > Overview > Recovery Password Configurations*.  
2. Review the configuration by clicking its name.  
3. Use the *Delete* button in the list view or on the configuration details page.  
4. Confirm the deletion when prompted.  

## HTTP API

### `/api/mdm/dep/devices/`

 * method: `GET`
 * required permission: `mdm.view_depdevice`
 * available filters:
    * `device_family`
    * `enrollment`
    * `profile_status`
    * `profile_uuid`
    * `serial_number`
    * `virtual_server`
 * available orderings:
    * `created_at`
    * `last_op_date`
    * `updated_at`
 * pagination:
    * `limit` (max `500`, `50` by default)
    * `offset`

Use this endpoint to list the DEP devices.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/mdm/dep/devices/?last_op_type=added&ordering=-last_op_date" \
  | python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 14,
            "virtual_server": 7,
            "serial_number": "XXXXXXXXXXXX",
            "asset_tag": "",
            "color": "SPACE GRAY",
            "description": "MBP 13.3 SPG/8C CPU/8C GPU",
            "device_family": "Mac",
            "model": "MacBook Pro 13\"",
            "os": "OSX",
            "device_assigned_by": "admin@example.com",
            "device_assigned_date": "2024-12-02T16:52:49",
            "last_op_type": "modified",
            "last_op_date": "2024-12-02T16:52:49",
            "profile_status": "pushed",
            "profile_uuid": "464921fa-a370-4bad-9a6f-9e3a8a73d94a",
            "profile_assign_time": "2024-12-01T13:12:11",
            "profile_push_time": "2024-12-02T16:02:47",
            "enrollment": 4,
            "disowned_at": null,
            "created_at": "2024-07-29T19:13:12.160287",
            "updated_at": "2024-12-03T16:46:26.703479"
        }
    ]
}
```

### `/api/mdm/dep/devices/<int:pk>/`

 * methods: `GET`, `PUT`
 * required permission: `mdm.view_depdevice`, `mdm.change_depdevice`

Use this endpoint to get a DEP device detail information and change its enrollment.

Example to get the DEP device detail information:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/dep/devices/14/ \
  | python3 -m json.tool
```

Response:

```json
{
    "id": 14,
    "virtual_server": 7,
    "serial_number": "XXXXXXXXXXXX",
    "asset_tag": "",
    "color": "SPACE GRAY",
    "description": "MBP 13.3 SPG/8C CPU/8C GPU",
    "device_family": "Mac",
    "model": "MacBook Pro 13\"",
    "os": "OSX",
    "device_assigned_by": "admin@example.com",
    "device_assigned_date": "2024-12-02T16:52:49",
    "last_op_type": "modified",
    "last_op_date": "2024-12-02T16:52:49",
    "profile_status": "pushed",
    "profile_uuid": "464921fa-a370-4bad-9a6f-9e3a8a73d94a",
    "profile_assign_time": "2024-12-01T13:12:11",
    "profile_push_time": "2024-12-02T16:02:47",
    "enrollment": 4,
    "disowned_at": null,
    "created_at": "2024-07-29T19:13:12.160287",
    "updated_at": "2024-12-03T16:46:26.703479"
}
```

Example to assign an enrollment/profile:

```bash
curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" -d '{"enrollment": 4}' \
  https://$ZTL_FQDN/api/mdm/dep/devices/14/ \
  | python3 -m json.tool
```

Response:

```json
{
    "id": 14,
    "virtual_server": 7,
    "serial_number": "XXXXXXXXXXXX",
    "asset_tag": "",
    "color": "SPACE GRAY",
    "description": "MBP 13.3 SPG/8C CPU/8C GPU",
    "device_family": "Mac",
    "model": "MacBook Pro 13\"",
    "os": "OSX",
    "device_assigned_by": "admin@example.com",
    "device_assigned_date": "2024-12-02T16:52:49",
    "last_op_type": "modified",
    "last_op_date": "2024-12-02T16:52:49",
    "profile_status": "pushed",
    "profile_uuid": "464921fa-a370-4bad-9a6f-9e3a8a73d94a",
    "profile_assign_time": "2024-12-03T16:46:26",
    "profile_push_time": null,
    "enrollment": 4,
    "disowned_at": null,
    "created_at": "2024-07-29T19:13:12.160287",
    "updated_at": "2024-12-03T16:46:26.703479"
}
```

### `/api/mdm/dep/devices/<int:pk>/disown/`

 * methods: `POST`
 * required permission: `mdm.disown_depdevice`

Use this endpoint to get a DEP device detail information and change its enrollment.

Example to get the DEP device detail information:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/dep/devices/14/disown/ \
  | python3 -m json.tool
```

Response:

```json
{
    "result": "SUCCESS"
}
```

### `/api/mdm/dep/virtual_servers/<int:pk>/sync_devices/`

 * method: `POST`
 * required permission: `mdm.view_depvirtualserver`

Use this endpoint to trigger a DEP virtual server devices sync.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/dep/virtual_servers/1/sync_devices/ \
  | python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd4",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd4/"
}
```

### `/api/mdm/devices/`

 * method: `GET`
 * required permission: `mdm.view_enrolleddevice`
 * available filters:
     * `serial_number`
     * `udid`
     * `tags`
     * `excluded_tags`

Use this endpoint to list the MDM enrolled devices.

`tags` and `excluded_tags` can be repeated to specify multiple machine tags. The `ID` of the tags must be used.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/?serial_number=012345678910
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 27,
            "udid": "2A7F9BCE-9B52-4073-BE21-E419C85068E9",
            "serial_number": "012345678910",
            "name": "John’s Mac mini",
            "users": [
              {
                "id": 29,
                "enrollment_id": null,
                "user_id": "0D3E9724-6740-4115-BCC8-3045285AF8C5",
                "long_name": "John Smith",
                "short_name": "john",
                "declarative_management": true,
                "last_ip": "1.1.1.1",
                "last_seen_at": "2024-02-17T20:31:35.148923",
                "created_at": "2023-08-06T14:44:02.829422",
                "updated_at": "2024-02-17T20:31:35.149274"
              }
            ],
            "model": "Mac14,2",
            "platform": "macOS",
            "os_version": "15.6.1",
            "build_version": "24G90",
            "apple_silicon": true,
            "cert_not_valid_after": "2026-09-05T14:32:40",
            "cert_att_serial_number": "012345678910",
            "cert_att_udid": "1111-2222-3333",
            "blueprint": 1,
            "awaiting_configuration": false,
            "declarative_management": true,
            "dep_enrollment": true,
            "user_enrollment": false,
            "user_approved_enrollment": true,
            "supervised": true,
            "bootstrap_token_escrowed": true,
            "filevault_enabled": true,
            "filevault_prk_escrowed": false,
            "recovery_password_escrowed": false,
            "admin_guid": null,
            "admin_shortname": null,
            "admin_password_escrowed": false,
            "activation_lock_manageable": true,
            "last_ip": "1.1.1.1",
            "last_seen_at": "2025-09-04T14:33:05.817386",
            "last_notified_at": "2025-09-09T10:54:43.798841",
            "checkout_at": null,
            "blocked_at": null,
            "created_at": "2025-09-02T14:46:54.885897",
            "updated_at": "2025-09-04T14:33:05.817441"
        }
    ]
}
```

### `/api/mdm/devices/<int:pk>/admin_password/`

 * method: `GET`
 * required permission: `mdm.view_admin_password`

Returns the decrypted auto admin password for an MDM enrolled device.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/27/admin_password/
```

Response:

```json
{
  "id": 27,
  "serial_number": "012345678910",
  "admin_password": "ABCDEF-012345-ABCDEF-012345"
}
```

### `/api/mdm/devices/<int:pk>/block/`

 * method: `POST`
 * required permission: `mdm.change_enrolleddevice`

Blocks an enrolled device. Releases it from the MDM and denies further MDM enrollments. A serialized device is returned.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/27/block/
```

Response:

```json
{
  "id": 27,
  "udid": "2A7F9BCE-9B52-4073-BE21-E419C85068E9",
  "serial_number": "012345678910",
  "name": "John’s Mac mini",
  "users": [
    {
      "id": 29,
      "enrollment_id": null,
      "user_id": "0D3E9724-6740-4115-BCC8-3045285AF8C5",
      "long_name": "John Smith",
      "short_name": "john",
      "declarative_management": true,
      "last_ip": "1.1.1.1",
      "last_seen_at": "2024-02-17T20:31:35.148923",
      "created_at": "2023-08-06T14:44:02.829422",
      "updated_at": "2024-02-17T20:31:35.149274"
    }
  ],
  "model": "Macmini8,1",
  "platform": "macOS",
  "os_version": "14.2.1",
  "build_version": "23C71",
  "apple_silicon": false,
  "cert_not_valid_after": "2024-08-05T14:44:01",
  "cert_att_serial_number": "012345678910",
  "cert_att_udid": "1111-2222-3333",
  "blueprint": 1,
  "awaiting_configuration": false,
  "declarative_management": true,
  "dep_enrollment": true,
  "user_enrollment": false,
  "user_approved_enrollment": true,
  "supervised": true,
  "bootstrap_token_escrowed": true,
  "filevault_enabled": true,
  "filevault_prk_escrowed": true,
  "recovery_password_escrowed": false,
  "admin_guid": null,
  "admin_shortname": null,
  "admin_password_escrowed": false,
  "activation_lock_manageable": true,
  "last_ip": "1.1.1.1",
  "last_seen_at": "2024-02-17T20:31:34.848107",
  "last_notified_at": "2024-03-27T20:44:21.751091",
  "checkout_at": null,
  "blocked_at": "2024-02-04T07:03:12.345678",
  "created_at": "2023-08-06T14:44:01.847058",
  "updated_at": "2024-02-04T07:03:12.456789",
}
```

### `/api/mdm/devices/<int:pk>/unblock/`

 * method: `POST`
 * required permission: `mdm.change_enrolleddevice`

Unblocks an enrolled device. The device can enroll again. A serialized device is returned.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/27/unblock/
```

Response:

```json
{
  "id": 27,
  "udid": "2A7F9BCE-9B52-4073-BE21-E419C85068E9",
  "serial_number": "012345678910",
  "name": "John’s Mac mini",
  "users": [
    {
      "id": 29,
      "enrollment_id": null,
      "user_id": "0D3E9724-6740-4115-BCC8-3045285AF8C5",
      "long_name": "John Smith",
      "short_name": "john",
      "declarative_management": true,
      "last_ip": "1.1.1.1",
      "last_seen_at": "2024-02-17T20:31:35.148923",
      "created_at": "2023-08-06T14:44:02.829422",
      "updated_at": "2024-02-17T20:31:35.149274"
    }
  ],
  "model": "Macmini8,1",
  "platform": "macOS",
  "os_version": "14.2.1",
  "build_version": "23C71",
  "apple_silicon": false,
  "cert_not_valid_after": "2024-08-05T14:44:01",
  "cert_att_serial_number": "012345678910",
  "cert_att_udid": "1111-2222-3333",
  "blueprint": 1,
  "awaiting_configuration": false,
  "declarative_management": true,
  "dep_enrollment": true,
  "user_enrollment": false,
  "user_approved_enrollment": true,
  "supervised": true,
  "bootstrap_token_escrowed": true,
  "filevault_enabled": true,
  "filevault_prk_escrowed": true,
  "recovery_password_escrowed": false,
  "admin_guid": null,
  "admin_shortname": null,
  "admin_password_escrowed": false,
  "activation_lock_manageable": true,
  "last_ip": "1.1.1.1",
  "last_seen_at": "2024-02-17T20:31:34.848107",
  "last_notified_at": "2024-03-27T20:44:21.751091",
  "checkout_at": null,
  "blocked_at": null,
  "created_at": "2023-08-06T14:44:01.847058",
  "updated_at": "2024-02-17T20:31:34.848262"
}
```

### `/api/mdm/devices/<int:pk>/erase/`

 * method: `POST`
 * required permission: `mdm.add_devicecommand`
 * arguments:
     * `disallow_proximity_setup`
     * `preserve_data_plan`
     * `pin`

Queues up an [EraseDevice](https://developer.apple.com/documentation/devicemanagement/erase_a_device) command for the device and notifies it.

On an Apple Silicon device, no arguments are required. For a T1 machine, the `pin` argument is required. For a mobile device, no `pin` can be set, but `disallow_proximity_setup` and `preserve_data_plan` are required.

A serialized device command is returned.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
  https://$ZTL_FQDN/api/mdm/devices/27/erase/
```

Response:

```json
{
  "id": 815,
  "uuid": "4ec709ba-542e-4adf-8002-7d782e9eae9e",
  "enrolled_device": 27,
  "name": "EraseDevice",
  "artifact_version": null,
  "artifact_operation": null,
  "not_before": null,
  "time": null,
  "result": null,
  "result_time": null,
  "status": null,
  "error_chain": null,
  "created_at": "2024-03-28T16:27:05.829954",
  "updated_at": "2024-03-28T16:27:05.829959"
}
```

### `/api/mdm/devices/<int:pk>/filevault_prk/`

 * method: `GET`
 * required permission: `mdm.view_filevault_prk`

Returns the decrypted FileVault PRK for an MDM enrolled device.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/27/filevault_prk/
```

Response:

```json
{
  "id": 27,
  "serial_number": "012345678910",
  "filevault_prk": "0000-0000-0000-0000-0000-0000"
}
```

### `/api/mdm/devices/<int:pk>/lock/`

 * method: `POST`
 * required permission: `mdm.add_devicecommand`
 * arguments:
     * `message`
     * `phone_number`
     * `pin`

Queues up a [DeviceLock](https://developer.apple.com/documentation/devicemanagement/lock_a_device) command for the device and notifies it.

`pin` can only be set, and is required for macOS devices. `message` and `phone_number` are optional.

A serialized device command is returned.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pin": "012345", "message": "This device is locked!", "phone_number": "+49000000000"}'
  https://$ZTL_FQDN/api/mdm/devices/27/lock/
```

Response:

```json
{
  "id": 815,
  "uuid": "4ec709ba-542e-4adf-8002-7d782e9eae9e",
  "enrolled_device": 27,
  "name": "DeviceLock",
  "artifact_version": null,
  "artifact_operation": null,
  "not_before": null,
  "time": null,
  "result": null,
  "result_time": null,
  "status": null,
  "error_chain": null,
  "created_at": "2024-03-28T16:27:05.829954",
  "updated_at": "2024-03-28T16:27:05.829959"
}
```

### `/api/mdm/devices/<int:pk>/recovery_password/`

 * method: `GET`
 * required permission: `mdm.view_recovery_password`

Returns the decrypted recovery lock or firmware password for an MDM enrolled device.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/27/recovery_password/
```

Response:

```json
{
  "id": 27,
  "serial_number": "012345678910",
  "recovery_password": "000000000000"
}
```

### `/api/mdm/devices/<int:pk>/send_custom_command/`

 * method: `POST`
 * required permission: `mdm.add_devicecommand`
 * arguments:
     * `command`

Queues up a custom command for the device and notifies it.

`command` is the raw `Command` value of an MDM command serialized as a plist (the `<plist/>` encapsulation can be omitted).

A serialized device command is returned.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "<dict><key>RequestType</key><string>EnableRemoteDesktop</string></dict>"}' \
  https://$ZTL_FQDN/api/mdm/devices/27/send_custom_command/ | python -m json.tool
```

Response:

```json
{
  "uuid": "4ec709ba-542e-4adf-8002-7d782e9eae9e",
  "enrolled_device": 27,
  "name": "CustomCommand",
  "artifact_version": null,
  "artifact_operation": null,
  "not_before": null,
  "time": null,
  "result": null,
  "result_time": null,
  "status": null,
  "error_chain": null,
  "created_at": "2024-03-28T16:27:05.829954",
  "updated_at": "2024-03-28T16:27:05.829959"
}
```

### `/api/mdm/devices/commands/`

 * method: `GET`
 * required permission: `mdm.view_devicecommand`
 * available filters:
     * `name`
     * `enrolled_device`

Fetches a list of MDM device commands.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/mdm/devices/commands/?name=SecurityInfo" | python -m json.tool
```

Response:

```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "uuid": "e2ff6623-b3c6-4d69-8065-ded674088d5a",
            "enrolled_device": 32,
            "name": "SecurityInfo",
            "artifact_version": null,
            "artifact_operation": null,
            "not_before": null,
            "time": "2024-11-22T21:38:47.051656",
            "result": null,
            "result_time": "2024-11-22T21:38:47.283399",
            "status": "Acknowledged",
            "error_chain": null,
            "created_at": "2024-10-27T14:36:07.027790",
            "updated_at": "2024-11-22T21:38:47.283567"
        },
        {
            "uuid": "4c7c4de6-0bb3-4b64-b1ef-d74910a73a7b",
            "enrolled_device": 31,
            "name": "SecurityInfo",
            "artifact_version": null,
            "artifact_operation": null,
            "not_before": null,
            "time": "2024-07-01T13:30:03.016001",
            "result": null,
            "result_time": "2024-07-01T13:30:03.313209",
            "status": "Acknowledged",
            "error_chain": null,
            "created_at": "2024-07-01T13:30:03.016245",
            "updated_at": "2024-07-01T13:30:03.313332"
        }
    ]
}
```

### `/api/mdm/devices/commands/<uuid.uuid>/`

 * method: `GET`
 * required permission: `mdm.view_devicecommand`

Fetches one MDM device command.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/mdm/devices/commands/e2ff6623-b3c6-4d69-8065-ded674088d51/" | python -m json.tool
```

Response:

```json
{
    "uuid": "e2ff6623-b3c6-4d69-8065-ded674088d51",
    "enrolled_device": 32,
    "name": "SecurityInfo",
    "artifact_version": null,
    "artifact_operation": null,
    "not_before": null,
    "time": "2024-11-22T21:38:47.051656",
    "result": null,
    "result_time": "2024-11-22T21:38:47.283399",
    "status": "Acknowledged",
    "error_chain": null,
    "created_at": "2024-10-27T14:36:07.027790",
    "updated_at": "2024-11-22T21:38:47.283567"
}
```


### `/api/mdm/locations/`

 * method: `GET`
 * required permission: `mdm.view_location`
 * available filters:
     * `name`
     * `organization_name`

Fetches the list of Apps / Books locations.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/locations/
```

Result:

```json
[
  {
    "id": 388,
    "server_token_expiration_date": "2050-01-01T00:00:00",
    "organization_name": "Organization name",
    "name": "Location name",
    "country_code": "DE",
    "library_uid": "1dc05825-af1d-422a-9b26-72a2f8c2aae5",
    "platform": "enterprisestore",
    "website_url": "https://business.apple.com",
    "mdm_info_id": "f42d9d70-d304-4ac1-83db-b045fa4bc623",
    "created_at": "2024-03-28T17:58:15.948083",
    "updated_at": "2024-03-28T17:58:15.948088"
  }
]
```

### `/api/mdm/location_assets/`

 * method: `GET`
 * required permission: `mdm.view_locationasset`
 * available filters:
     * `adam_id`
     * `pricing_param`
     * `location_id`

Fetches the list of Apps / Books location assets.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/location_assets/?location_id=749
```

Result:

```json
[
  {
    "id": 414,
    "assigned_count": 0,
    "available_count": 0,
    "retired_count": 0,
    "total_count": 0,
    "created_at": "2024-03-28T19:15:58.212233",
    "updated_at": "2024-03-28T19:15:58.212237",
    "location": 749,
    "asset": 489
  }
]
```

### `/api/mdm/software_updates/sync/`

 * method: `POST`
 * required permission:
    * `mdm.add_softwareupdate`
    * `mdm.change_softwareupdate`
    * `mdm.delete_softwareupdate`

Use this endpoint to trigger a Software Updates sync.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/software_updates/sync/ \
  | python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd4",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd4/"
}
```

### `/api/mdm/users/commands/`

 * method: `GET`
 * required permission: `mdm.view_usercommand`
 * available filters:
     * `name`
     * `enrolled_user`

Fetches a list of MDM user commands.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/mdm/users/commands/?name=InstallProfile" | python -m json.tool
```

Response:

```json
{
    "count": 2,
    "next": null,
    "previous": null,
    "results": [
        {
            "uuid": "c9e3829e-ce6a-4ee2-a286-4b83b574d04a",
            "enrolled_user": 24,
            "name": "InstallProfile",
            "artifact_version": "fe4ed451-ad0b-4f32-8ff6-25614368bdb1",
            "artifact_operation": "Installation",
            "not_before": null,
            "time": "2022-08-26T14:46:46.635801",
            "result": null,
            "result_time": "2022-08-26T14:46:48.906815",
            "status": "Acknowledged",
            "error_chain": null,
            "created_at": "2022-08-26T14:46:46.636222",
            "updated_at": "2022-08-26T14:46:48.906948"
        },
        {
            "uuid": "c0c4c26f-1d97-41cc-b82d-ef65824cdeb8",
            "enrolled_user": 23,
            "name": "InstallProfile",
            "artifact_version": "fe4ed451-ad0b-4f32-8ff6-25614368bdb1",
            "artifact_operation": "Installation",
            "not_before": null,
            "time": "2022-08-26T14:42:56.311863",
            "result": null,
            "result_time": "2022-08-26T14:42:58.413435",
            "status": "Acknowledged",
            "error_chain": null,
            "created_at": "2022-08-26T14:42:56.312212",
            "updated_at": "2022-08-26T14:42:58.413625"
        }
    ]
}
```

### `/api/mdm/users/commands/<uuid.uuid>/`

 * method: `GET`
 * required permission: `mdm.view_usercommand`

Fetches one MDM user command.

Example:

```bash
curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/mdm/users/commands/c0c4c26f-1d97-41cc-b82d-ef65824cdeb8/" | python -m json.tool
```

Response:

```json
{
    "uuid": "c0c4c26f-1d97-41cc-b82d-ef65824cdeb8",
    "enrolled_user": 23,
    "name": "InstallProfile",
    "artifact_version": "fe4ed451-ad0b-4f32-8ff6-25614368bdb1",
    "artifact_operation": "Installation",
    "not_before": null,
    "time": "2022-08-26T14:42:56.311863",
    "result": null,
    "result_time": "2022-08-26T14:42:58.413435",
    "status": "Acknowledged",
    "error_chain": null,
    "created_at": "2022-08-26T14:42:56.312212",
    "updated_at": "2022-08-26T14:42:58.413625"
}
```
