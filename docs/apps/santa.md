# Santa

[Santa](https://santa.readthedocs.io/en/latest/) is a binary authorization system for macOS. Zentral can act as a [sync server](https://santa.readthedocs.io/en/latest/introduction/syncing-overview/) for Santa, to configure the rules, and collect the events.

## Zentral configuration

To activate the santa module, you need to add a `zentral.contrib.santa` section to the `apps` section in `base.json`.

## Santa deployment

### Create a Santa agent configuration

In Zentral, go to Setup > Santa configurations. Click on the [Create] button. The form mirrors the [Santa configuration keys](https://santa.readthedocs.io/en/latest/deployment/configuration/) (some of them are omitted and will be set automatically by Zentral).

**WARNING** be careful and do not configure Santa in lockdown mode unless you know what you are doing!!!

You can start with the default values, and simply pick a name (must be unique) for the configuration, then click the [Save] button at the bottom.


### Create an enrollment

Once you have created a Santa configuration in Zentral, you can create an enrollement for it using the [Create] button in the Enrollment section of the configuration. An enrollment is a configuration that is applied to the machines the first time the Santa agent makes a preflight query to Zentral.

#### Machine segmentation

You can pick a Meta business unit to segment your machines. You can also segment the machines during the enrollment by picking tags.

#### Enrollment restrictions

Enrollments can be restricted by machine serial numbers and UUIDs – all machines are allowed if the `Serial numbers` and `UUIDs` fields are left blank. You can also set a maximum number of enrollments – machines will always be allowed if the `Quota` field is left blank.

#### Save and download

Save the enrollment form, you will be redirected to the configuration, and the new enrollment will be available. You can download two different versions of the enrollment:

 * a plist containing only the Santa specific configuration keys. This plist is can be uploaded to Jamf, to create a custom settings payload for the `com.google.santa` Preference Domain.
 * a configuration profile with a [ManagedPreferences](https://developer.apple.com/documentation/devicemanagement/managedpreferences) payload, that can be further customized or distributed as is.

#### How it works

Each enrollment has a secret associated with it, and this secret is part of the Santa `SyncBaseURL` that is set in the plists or configuration profiles when you download them. This is how Zentral associate machines with configurations. Machines can be re-enrolled to a different configuration by simply deploying a different santa payload. The old rules will be erased and replaced by the new configuration rules.


### Distribute the payloads

4 different payloads need to be distributed to configure and activate the Santa agent.

#### Main santa configuration

This is the payload that is generated when creating an enrollment on a Zentral santa configuration (see previous section.) You can further customize this payload to add for example the `MachineOwner` [Santa configuration key](https://santa.readthedocs.io/en/latest/deployment/configuration/) using [Jamf Payload Variables](https://docs.jamf.com/jamf-school/deploy-guide-docs/Payload_Variables.html).


#### Privacy preference policy control

Santa, the santa daemon, and the santa bundle service need access to all protected files, including system administration files. A [privacy preference policy control payload](https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol) must be distributed to allow the *System Policy All Files* (`SystemPolicyAllFiles` key) [Service](https://support.apple.com/guide/mdm/privacy-preferences-policy-control-payload-mdm38df53c2a/1/web/1.0#mdm00b8cbaf5) for these three santa components, identified by their bundle IDs and code requirements.

|IdentifierType|Identifier|CodeRequirement|Allowed|
|---|---|---|---|
|bundleID|com.google.santa|identifier "com.google.santa" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /\* exists \*/ and certificate leaf[field.1.2.840.113635.100.6.1.13] /\* exists \*/ and certificate leaf[subject.OU] = EQHXZ8M8AV|true|
|bundleID|com.google.santa.daemon|identifier "com.google.santa.daemon" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /\* exists \*/ and certificate leaf[field.1.2.840.113635.100.6.1.13] /\* exists \*/ and certificate leaf[subject.OU] = EQHXZ8M8AV|true|
|bundleID|com.google.santa.bundleservice|identifier "com.google.santa.bundleservice" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /\* exists \*/ and certificate leaf[field.1.2.840.113635.100.6.1.13] /\* exists \*/ and certificate leaf[subject.OU] = EQHXZ8M8AV|true|

Code requirements can be validated using the following command:

```
$ codesign -dr - \
  /Applications/Santa.app \
  /Applications/Santa.app/Contents/Library/SystemExtensions/com.google.santa.daemon.systemextension/Contents/MacOS/com.google.santa.daemon \
  /Applications/Santa.app/Contents/MacOS/santabundleservice
```

Everything after `designated =>`should be included in the profile.


#### System Extension

To listen for the [endpoint security](https://developer.apple.com/documentation/endpointsecurity) events, and be able to act on them, santa installs a system extension. To activate this system extension, a [SystemExtensions payload](https://developer.apple.com/documentation/devicemanagement/systemextensions) needs to be distributed.

|Key|Team Identifier|Value|
|---|---|---|
|AllowedSystemExtensionTypes|EQHXZ8M8AV|EndpointSecurityExtension|
|AllowedSystemExtensions|EQHXZ8M8AV|com.google.santa.daemon|

The values can be validated using the following command:

```
$ systemextensionsctl list
```

[Payload documentation](https://developer.apple.com/documentation/devicemanagement/systemextensions)


#### Notifications

Santa notifies the user when the main mode is changed (Lockdown / Monitor). To allow those notifications, a [Notifications payload](https://developer.apple.com/documentation/devicemanagement/notifications) needs to be distributed.

The payload is an array of [NotificationSettingItem](https://developer.apple.com/documentation/devicemanagement/notifications/notificationsettingsitem). Suggested values:

|Key|Value|
|---|---|
|AlertType|1|
|BadgesEnabled|true|
|BundleIdentifier|com.google.santa|
|CriticalAlertEnabled|true|
|NotificationsEnabled|true|
|ShowInLockScreen|true|
|ShowInNotificationCenter|true|
|SoundsEnabled|false|


## Santa rules

### Definitions

Zentral Santa rule combine a *target* and a *policy*. The target can be of type `Binary`, `Bundle` or `Certificate`. A target is uniquely identified by its type, and its sha256. The policy can be one of `Allowlist`, `Blocklist`, `Silent blocklist` and `Allowlist compiler`.

To avoid conflicts, there is at most **one rule per target** for each configuration.

**Rule precedence** applies. You can have a `Blocklist` rule on a certificate, and an `Allowlist` rule on one of the binaries signed using the certificate.

**Bundle** targets are only available when Zentral managed to get the full bundle information from Santa. This happens only when Santa blocks a binary that is part of a bundle, and when `Enable bundles` is set to true in the Zentral Santa configuration. Rules on a bundle target only exist in Zentral. There are expanded to a list of binary rules when sent to the Santa agent – this is the reason why we need the bundle information.

**Allowlist compiler** rules will only generate local transitive rules when `Enable transitive rules` is set to true in the Zentral Santa configuration. A transitive Allowlist rule will be created locally for each file written by the targets of those Santa rules.

### Quick start

On any Zentral configuration page (the one with the configuration information and the enrollments), there is a "Rules" sub section at the bottom, with a count and a [Manage rules] button. Click on it to access the configuration rule list.

You can filter the list using the search form at the top. From this list, you can edit or delete existing rules (if they are not part of a ruleset, see API section below), and add more rules. To add a rule, click on the [Add] button at the top, and select the kind of rule you want to add. We will start with a "Base rule".

To get the necessary information about a binary or a certificate you want to block or allow, use the [`santactl fileinfo` command](https://santa.readthedocs.io/en/latest/details/santactl/#fileinfo).

Once you have set the rule type, the sha256 and the policy, you can click on the [Save] button, and the rule will be added to the configuration for all the machines.

If you do not want to wait for a full sync to happen on your machine, you can trigger one using the following command:

```
$ sudo santactl sync
```

You should see a rule being downloaded in the command output.

### Rule forms

Zentral is collecting information about all the binary, bundles and certificates that are present in the events that Santa uploads.

Using this information, it is possible to build a rule without knowing the sha256, using the "Binary rule", "Bundle rule" or "Certificate rule" options in Rules > [Add] dropdown menu. But it might be that the binary, bundle or certificate information is not in Zentral. In that case, use the "Base rule" form.

### Rule scope

By default, a rule will be synced to all the machines enrolled on its Zentral Santa configuration.

Rules can be scoped to machine serial numbers. A list of serial numbers separated by `,` can be used in the `Serial numbers` field of the rule forms.

Rules can also be scoped to machine primary users. A list of primary user (id, emails, …) separated by `,` can be used in the `Primary users` field of the rule forms. If one of them matches the primary user reported by Santa, the rule will be in scope. For this to be effective, you need to configure the primary user reported by Santa using either the `MachineOwner` key of the Santa payload, or the combination of the `MachineOwnerPlist` and `MachineOwnerKey` keys, with local plists on each machine.

Finally, rules can be scoped to machine tags. Select the matching tags in the rule forms.

**IMPORTANT:** The rule is in scope if **any** serial number, primary user or tag is a match.

## Santa sync

The Santa agent is configured to sync periodically with the Zentral server. The `Full sync interval` can be adjusted for each Santa configuration – 10 min by default, cannot be shorter than 10 min. No need to distribute the updated Santa payload. The agent will apply the new interval during the next sync.

To check the santa sync configuration and status, use the following command:

```
$ santactl status
```

Verify that the `Sync Server` URL is pointing to your Santa server.

To manually trigger a full synchronization (for example, for applying new rules without having to wait for a full sync interval), use the following command:

```
$ sudo santactl sync
```

A full synchronization has 4 phases:

### Preflight

The Santa agent sends some information about the system (os version, identifiers, …) and itself (version, number of rule for each rule types, …). Zentral responds with the updated [sync server provided configuration](https://santa.readthedocs.io/en/latest/deployment/configuration/#sync-server-provided-configuration). Using this mechanism, some of the updated Zentral Santa configuration attributes will be applied without having to deploy new payloads. For example, it is possible to switch from Monitor to Lockdown mode, or to increase the full sync interval to 20min.

Zentral will also request a clean sync if the machine is new – never seen before or previonsly enrolled on a different configuration. Santa will delete all the existing rule in the local database during a clean sync.

### Events upload

The Santa agent will then proceed to upload the events it has gathered. These are for example `ALLOW UNKNOWN` execution events for binaries not targeted by any rule in Monitor mode. These events contain useful information about the binaries and their signatures, that Zentral stores to help you build the necessary rules for your deployment. You can change the number of events sent in one request using the `Batch size` attribute of the Zentral Santa configurations. This attribute is part of the dynamic sync server configuration and is applied during each preflight phase – no need to distribute a new santa payload.

**NB:** Block events are usually sent when they happen, outside of the full synchronization.

### Rules download

Once the events have been uploaded, the rules are downloaded. Zentral will send batches of `Batch size` rules, and only mark them as present on the machine when Santa asks for the next batch. Rules that have been deleted, or are not anymore in scope for the machine will be removed.

### Postflight

Santa finally makes an extra request to indicate the end of the full synchronization.
