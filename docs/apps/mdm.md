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

* Navigate to the Zentral *MDM > Overview > Push certificates* section.
* Open the `Zentral Cloud` certificate detail page.
* Click on the button to download a signed CSR `push_certificate_signed_csr.b64` file.
* Sign in to the [Apple Push Certificate Portal](https://identity.apple.com).
* Upload the `push_certificate_signed_csr.b64` signed certificate request file.
* Download the generated APNs certificate.
* Return to the Zentral *MDM > Overview > Push certificates > Zentral Cloud* certificate detail page. 
* Upload the generated APNs certificate.

This configuration is now ready for Zentral MDM push capabilities. To renew an existing push certificate, repeat those steps. 

**IMPORTANT** do not let the push/APNS certificates expire! Remember to renew them ahead of their expiry!

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

**IMPORTANT** do not let the push/APNS certificates expire! Remember to renew them ahead of their expiry!

To be able to keep sending notifications to enrolled devices, it is important to renew the existing certificates, and not generate new ones (it is important that the *topic* of a push certificate stays the same). In the [Apple Push Certificate Portal](https://identity.apple.com), look for the existing certificate and click on the `Renew` button, and not on the `Create a Certificate` button. In the Zentral *MDM > Push certificates* section, find the certificate and click on the *Update* button, and do not *Add* a new certificate.


## Automated Device Enrollment

To use modern automated device enrollment with Zentral, you need to ensure proper synchronization with Apple Business Manager (ABM) or Apple School Manager (ASM). This synchronization requires an MDM server token.

### Prerequisites

- Access to Apple Business Manager (ABM) or Apple School Manager (ASM).
- An MDM server token for syncing with ABM/ASM.

For detailed instructions on general ABM/ASM usage, refer to the [Apple Business Manager User Guide](https://support.apple.com/en-ca/guide/apple-business-manager/welcome/web).


### Configure Automated Device Enrollment (formerly known as DEP)

To set up Automated Device Enrollment (ADE) to work with Zentral, follow these steps:

* Navigate to the Zentral *MDM > Overview > DEP Virtual Servers* section and click the *Connect* button. Do not close this section during the process.
* Download the new public key.
* In ABM/ASM go to the *Preferences > Your MDM Servers > MDM Server Settings* section.
* Add a new MDM Server or click *Edit* on an existing MDM Server to replace the public key.
* Download the `MDM server token` from the *MDM Server Information* section in ABM/ASM.
* Return to Zentral and upload the `MDM server token` in the *MDM > Overview > DEP Virtual Servers* section.
* Once an *Enrollment* profile has been created (see the section below), you can assign it as the default enrollment for this token.

To fully utilize ADE, you need to create an *Enrollment* in the *MDM > Overview > Enrollment* section and select the appropriate *Virtual Server* during the setup process (see below). The assigned *Enrollment* will be reflected in the *MDM > DEP Virtual Servers > [Instance Name] > Profile* section, and the devices assigned in ABM/ASM will appear in the *MDM > DEP Virtual Servers > [Instance Name] > Devices* section.

The device assignments will sync automatically. If the existing device assignments in ABM/ASM are not reflected in Zentral, go to the *MDM > DEP Virtual Servers > [Instance Name]* section and manually click the `Synchronize` button. The devices will also be visible in the *MDM > Overview > DEP Devices* section.

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

## HTTP API

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

Use this endpoint to list the MDM enrolled devices.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/mdm/devices/?serial_number=012345678910
```

Response:

```json
[
  {
    "id": 27,
    "udid": "2A7F9BCE-9B52-4073-BE21-E419C85068E9",
    "serial_number": "012345678910",
    "name": "John’s Mac mini",
    "model": "Macmini8,1",
    "platform": "macOS",
    "os_version": "14.2.1",
    "build_version": "23C71",
    "apple_silicon": false,
    "cert_not_valid_after": "2024-08-05T14:44:01",
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
    "activation_lock_manageable": true,
    "last_seen_at": "2024-02-17T20:31:34.848107",
    "last_notified_at": "2024-03-27T20:44:21.751091",
    "checkout_at": null,
    "blocked_at": null,
    "created_at": "2023-08-06T14:44:01.847058",
    "updated_at": "2024-02-17T20:31:34.848262"
  }
]
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
  "model": "Macmini8,1",
  "platform": "macOS",
  "os_version": "14.2.1",
  "build_version": "23C71",
  "apple_silicon": false,
  "cert_not_valid_after": "2024-08-05T14:44:01",
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
  "activation_lock_manageable": true,
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
  "model": "Macmini8,1",
  "platform": "macOS",
  "os_version": "14.2.1",
  "build_version": "23C71",
  "apple_silicon": false,
  "cert_not_valid_after": "2024-08-05T14:44:01",
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
  "activation_lock_manageable": true,
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
