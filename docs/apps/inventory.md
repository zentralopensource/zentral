# Inventory

The Zentral Inventory app is used to store all the information about the hardware, software and configuration assets in a unified model. The information comes from the agents managed by Zentral, or from third party inventory sources when an agent managed by Zentral cannot be deployed on the devices. Compliance checks can be configured to run on each device inventory update.

This Zentral module is mandatory in each deployment.

## Available sources

|Name|Type|Platforms|Basic info|Apps|Extra info|
|---|---|---|---|---|---|
|Apple MDM|Agent|Apple|✅|✅|✅|
|Munki|Agent|macOS|✅|✅|✅|
|Osquery|Agent|multiplatform|✅|✅|✅|
|Santa|Agent|macOS|✅| | |
|Jamf|3rd party|Apple|✅|✅|✅|
|Puppet|3rd party|multiplatform|✅|✅|✅|
|Workspace ONE|3rd party|multiplatform|✅|✅|✅|

## Architecture

![Zentral inventory architecture](../../images/apps/inventory/architecture.svg)

### Inventory data collection

#### Agents

The managed agents running on each device push inventory data at regular intervals to the Zentral frontend using their custom format and protocol over HTTPS. The inventory data collection for some agents can be dynamically configured by Zentral, with for example the option to collect AWS EC2 instance metadata for Osquery, or Munki custom facts.

#### Third party inventory

The inventory data of third party systems is usually collected using a notify/pull system for efficiency reasons. When an asset is updated in the third party system, a notification (a webhook for example) is sent to Zentral, and an inventory update task is queued. A background worker will pickup the task, and query the inventory for more detailed information about the asset. This allows the notification to be quickly processed. The potentially slower API call to the inventory happens in the background, with a queue to store the tasks in case the inventory is unavailable. This is also efficient, because only the updated data is pulled from the inventory.

If the third party system cannot notify Zentral when assets are updated, a Zentral background worker can also pull the full inventory data at regular intervals.

### Inventory storage

#### Normalisation

The inventory data that is collected is first normalised before being stored. A unified schema is used for all inventory sources, allowing the comparison, aggregation and processing of the inventory data across multiple sources:

 * Business unit
 * Groups

 * System info
 * Hardware info
 * OS version
 * Disks
 * Network Interfaces
 * Principal user
 * Extra facts (custom key/value)
 * Links

 * macOS apps
 * macOS app instances (macOS app + path)
 * Debian packages
 * Windows programs
 * Windows program instances (Windows program + path)
 * Android apps
 * iOS apps

 * Certificates
 * Apple configuration profiles

 * EC2 instance metadata
 * EC2 instance tags
 * Puppet node

#### Storage

Once the data has been normalised, it is stored in the main database (PostgreSQL). For each device and source, complete inventory updates are stored in the form of snapshots, with a special object pointing to the current snapshot for each device and source. 

If the inventory data sent by an agent, once normalised, results in a snapshot that is already present in the database, only the information about the current snapshot for this device and source (last seen) is updated. If the snapshot is different from the last one for the same source and device, it is stored in the database, with a reference to the previous one, and the current snapshot for the device and source is updated to point to the new snapshot.

The assets like OS versions, or macOS apps are deduplicated. If the same application is installed on two different Apple laptops, only one macOS app object is created in the database.

This is similar to the Git object store: device snapshots can be compared to Git trees, assets to Git objects and the current snapshot for a given source to a Git branch.

The retention of the snapshots [can be configured](#snapshot_retention_days). A background task is scheduled to prune the older snapshots while preserving the most recent one for each device and source.

### Inventory events

When an updated inventory snapshot is received for a device and a source, Zentral computes the difference with the previous snapshot, and emits events for each asset update. This is a list of all the Zentral machine update events:

|Asset|Event type|Event tags|
|---|---|---|
|Business Unit|`add_machine_business_unit`|`machine`, `machine_update`, `machine_add_update`|
|Business Unit|`remove_machine_business_unit`|`machine`, `machine_update`, `machine_remove_update`|
|Group|`add_machine_group`|`machine`, `machine_update`, `machine_add_update`|
|Group|`remove_machine_group`|`machine`, `machine_update`, `machine_remove_update`|
|System Info|`add_machine_system_info`|`machine`, `machine_update`, `machine_add_update`|
|System Info|`remove_machine_system_info`|`machine`, `machine_update`, `machine_remove_update`|
|Os Version|`add_machine_os_version`|`machine`, `machine_update`, `machine_add_update`|
|Os Version|`remove_machine_os_version`|`machine`, `machine_update`, `machine_remove_update`|
|Disk|`add_machine_disk`|`machine`, `machine_update`, `machine_add_update`|
|Disk|`remove_machine_disk`|`machine`, `machine_update`, `machine_remove_update`|
|Network Interface|`add_machine_network_interface`|`machine`, `machine_update`, `machine_add_update`|
|Network Interface|`remove_machine_network_interface`|`machine`, `machine_update`, `machine_remove_update`|
|Principal User|`add_machine_principal_user`|`machine`, `machine_update`, `machine_add_update`|
|Principal User|`remove_machine_principal_user`|`machine`, `machine_update`, `machine_remove_update`|
|Extra Facts|`add_machine_extra_facts`|`machine`, `machine_update`, `machine_add_update`|
|Extra Facts|`remove_machine_extra_facts`|`machine`, `machine_update`, `machine_remove_update`|
|Link|`add_machine_link`|`machine`, `machine_update`, `machine_add_update`|
|Link|`remove_machine_link`|`machine`, `machine_update`, `machine_remove_update`|
|Osx App Instance|`add_machine_osx_app_instance`|`machine`, `machine_update`, `machine_add_update`|
|Osx App Instance|`remove_machine_osx_app_instance`|`machine`, `machine_update`, `machine_remove_update`|
|Deb Package|`add_machine_deb_package`|`machine`, `machine_update`, `machine_add_update`|
|Deb Package|`remove_machine_deb_package`|`machine`, `machine_update`, `machine_remove_update`|
|Program Instance|`add_machine_program_instance`|`machine`, `machine_update`, `machine_add_update`|
|Program Instance|`remove_machine_program_instance`|`machine`, `machine_update`, `machine_remove_update`|
|Android App|`add_machine_android_app`|`machine`, `machine_update`, `machine_add_update`|
|Android App|`remove_machine_android_app`|`machine`, `machine_update`, `machine_remove_update`|
|Ios App|`add_machine_ios_app`|`machine`, `machine_update`, `machine_add_update`|
|Ios App|`remove_machine_ios_app`|`machine`, `machine_update`, `machine_remove_update`|
|Certificate|`add_machine_certificate`|`machine`, `machine_update`, `machine_add_update`|
|Certificate|`remove_machine_certificate`|`machine`, `machine_update`, `machine_remove_update`|
|Profile|`add_machine_profile`|`machine`, `machine_update`, `machine_add_update`|
|Profile|`remove_machine_profile`|`machine`, `machine_update`, `machine_remove_update`|
|EC2 Instance Metadata|`add_machine_ec2_instance_metadata`|`machine`, `machine_update`, `machine_add_update`|
|EC2 Instance Metadata|`remove_machine_ec2_instance_metadata`|`machine`, `machine_update`, `machine_remove_update`|
|EC2 Instance Tag|`add_machine_ec2_instance_tag`|`machine`, `machine_update`, `machine_add_update`|
|EC2 Instance Tag|`remove_machine_ec2_instance_tag`|`machine`, `machine_update`, `machine_remove_update`|
|Puppet Node|`add_machine_puppet_node`|`machine`, `machine_update`, `machine_add_update`|
|Puppet Node|`remove_machine_puppet_node`|`machine`, `machine_update`, `machine_remove_update`|

All the above events are standard Zentral events, with the Zentral event metadata containing the machine information, event type, event tags. They are processed by the Zentral event pipeline, and can be filtered and shipped to third party event stores. Event probes can also be configured in Zentral to filter the events and trigger actions.

The inventory snapshot updates, even if they are not different from the stored snapshots, are also run through the compliance checks. For each compliance check in scope for the source / device / platform, the status is computed, and if the status has changed, an `inventory_jmespath_check_status_updated` event is created.

## Compliance checks

### How it works

Compliance checks can be configured to verify the device inventory snapshots. When an inventory update is received (agent) or pulled (3rd party inventory), Zentral fetches the compliance checks in scope for the update, and for each one of them computes its status. If the status has changed, the status for the given device and compliance check is updated in the main database (PostgreSQL) and an `inventory_jmespath_check_status_updated` event is created.

The Zentral inventory compliance checks are scoped using 3 criteria:

 * Inventory source
 * Platforms (Linux, macOS,  Windows, Android, iOS, iPadOS, tvOS)
 * Device tags

The check itself is a [JMESPath](https://jmespath.org/) expression that is evaluated against the full device inventory snapshot tree.

### Example

To test an inventory compliance check:

 * Go to *Inventory > Compliance checks*, and click on the [DevTool] button. This will allow you to evaluate a JMESPath expression against the inventory snapshot tree of a given device and source.

 * Pick a source, and a serial number.

 * In the *JMESPath expression* field, use the following expression to check that the OS version on the device is `13.3.1`:

    ```
    os_version.major == `13` && os_version.minor == `3` && os_version.patch == `1`
    ```

 * Click on the [Test] button. You will see the result of the JMESPath expression, and also a full inventory snapshot tree for the source and device. You can now iterate on the JMESPath expression, and for example update it for the current version of macOS.

 * Once the JMESPath expression is correct, you can click on the [Create] button. This will bring you to a formular where you can pick a name, a description, and a source. You can also scope the compliance check to have it run only on some platforms, or for devices with some given tags.

 * Click on the [Save] button to finish creating the inventory compliance check.

The newly created inventory compliance check will now be evaluated for each scoped inventory update. The last status is available in each device inventory detail page. It will also contribute to the overall compliance status of the devices.

The same configuration can be achieved using a Terraform resource:

```tf
resource "zentral_jmespath_check" "macos-up-to-date" {
  name                = "macOS up to date"
  description         = "Check that the latest macOS version is running."
  source_name         = "munki"
  platforms           = ["MACOS"]
  jmespath_expression = "os_version.major == `13` && os_version.minor == `3` && os_version.patch == `1`"
}
```

## Zentral configuration

A `zentral.contrib.inventory` subsection must be present in the `apps` section in [the configuration](../../configuration).

### `snapshot_retention_days`

**OPTIONAL**

Number of days (integer) after which the inventory device snapshots are pruned. Defaults to `30`. **IMPORTANT** For each device and source combination, the most recent snapshot is always preserved.

### `metrics`

**OPTIONAL**

This boolean is used to toggle the inventory metrics endpoint for Prometheus. `false` by default.

### `metrics_options`

**OPTIONAL**

A dictionary to configure the available inventory metrics. Only configured metrics will be published. Empty by default.

Six different metric families are available: `android_apps`, `deb_packages`, `ios_apps`, `osx_apps`, `programs`, and `os_versions`. To publish a metric family, the corresponding configuration dictionary must be set in the `metrics_options` section. For each metric family, a mandatory `sources` attribute must be set, to filter the inventory sources. A mandatory `bundle_ids` or `bundle_names` attribute (array of strings) must be set in the `osx_apps` metric family configuration to filter the published bundle metrics. For the `android_apps`, `deb_packages`, `ios_apps`, and `programs` metric families, a `names` attribute (array of strings) must be set, respectively to the list of Android app names, Debian package names, iOS app names, or Windows program names to include in the metrics.

Example:

```json
{
  "metrics": true,
  "metrics_options": {
    "android_apps": {
      "sources": ["Workspace ONE"],
      "names": ["Google Pay"],
    },
    "deb_packages": {
      "sources": ["osquery"],
      "names": ["firefox", "falcon-sensor"]
    },
    "ios_apps": {
      "sources": ["Workspace ONE"],
      "names": ["1Password"],
    },
    "osx_apps": {
      "sources": ["Munki", "osquery"],
      "bundle_ids": ["org.mozilla.firefox", "us.zoom.xos"]
    },
    "programs": {
      "sources": ["osquery"],
      "names": ["Firefox", "Zoom"]
    },
    "os_versions": {
      "sources": ["Munki", "osquery"]
    }
  }
}
```


### `event_serialization`

**OPTIONAL**

This subsection can be used to change the machine information serialization in the Zentral event metadata. There are two options available:

#### `include_groups`

**OPTIONAL**

This boolean is used to toggle the inclusion of the machine groups in the event metadata. `true` by default.

#### `include_principal_user`

**OPTIONAL**

This boolean is used to toggle the inclusion of the principal user in the event metadata. `true` by default.

## HTTP API

### `/api/inventory/machines/tags/`

* method: POST
* required permissions:
    * `inventory.add_tag`
    * `inventory.add_taxonomy`
    * `inventory.add_machinetag`
    * `inventory.delete_machinetag`

Use this endpoint to tag machines using serial numbers or principal user information (unique IDs or principal names). Three different operations are possible: `ADD`, `REMOVE`, `SET`. For the `SET` operation, the `taxonomy` attribute is required. For the `REMOVE` operation, the `taxonomy` attribute must not be used. For the `ADD` operation and `REMOVE` operation, the `names` attribute must not be empty. To scope the machines, use either `serial_numbers` or `principal_users`.

Example payload to tag machines using their principal users:

```json
{
  "principal_users": {
    "principal_names": ["janeDoe", "johnSmith"],
    "unique_ids": ["max.mustermann@example.com"]
  },
  "operations": [
    {"kind": "SET", "taxonomy": "Department", "names": ["IT"]},
    {"kind": "REMOVE", "names": ["Orange", "Red"]},
    {"kind": "ADD", "taxonomy": "Branch", "names": ["Hamburg"]},
    {"kind": "ADD", "names": ["Blue"]}
  ]
}
```

When this payload is posted, Zentral looks for all the machines having matching principal users. For each machine, four operations are applied:

 1. make sure that a `IT` tag exists from the `Department` taxonomy, and remove any other tag from this taxonomy.
 2. remove any `Orange` or `Red` tags.
 3. add a `Hamburg` tag in the `Branch` taxonomy.
 4. add a `Blue` tag without taxonomy.

Example payload to tag machines using their serial numbers:

```json
{
  "principal_users": ["123456789", "987654321"],
  "operations": [
    {"kind": "SET", "taxonomy": "Department", "names": ["HR"]}
  ]
}
```

When this payload is posted, Zentral looks for all the machines having matching serial numbers. For each machine, one operations is applied:

 1. make sure that a `HR` tag exists from the `Department` taxonomy, and remove any other tag from this taxonomy.

The response format is:

```json
{
  "machines": {"found": 2},
  "tags": {"added": 2,
           "removed": 1}
}
```

### `/api/inventory/cleanup/`

* method: POST
* required permissions:
	* `inventory.delete_machinesnapshot`
* optional parameter:
	* `days`: The number of days (`1` → `3660`) of history to keep. Defaults to `30` or the value of `snapshot_retention_days` in the inventory app config.

Use this endpoint to trigger an inventory history cleanup.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/cleanup/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd4",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd4/"
}
```

### `/api/inventory/machines/archive/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.change_machinesnapshot`

Use this endpoint to archive machines using their serial numbers. The inventory data will be kept in the database, in case the machines show up again, but the machines will not be displayed when browsing or exporting the inventory. Up to 1000 machines can be archived per API call.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"serial_numbers": ["0123456789"]}' \
  https://zentral.example.com/api/inventory/machines/archive/\
  |python3 -m json.tool
```

Response:

```json
{"current_machine_snapshots": 0}
```

### `/api/inventory/machines/prune/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.delete_machinesnapshot`

Use this endpoint to prune machines using their serial numbers. The inventory data will be removed from the database. Up to 1000 machines can be pruned per API call.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"serial_numbers": ["0123456789"]}' \
  https://zentral.example.com/api/inventory/machines/prune/\
  |python3 -m json.tool
```

Response:

```json
{"current_machine_snapshots": 1,
 "machine_snapshots": 2,
 "machine_snapshot_commits": 13}
```

### `/api/inventory/android_apps/export/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.view_androidapp`
* optional parameters:
    * `export_format`: `csv` or `xlsx`. Defaults to `xlsx`.
    * `source`: The ID of an inventory source. Only Android apps collected via this source will be included in the export.
    * `last_seen`: `1d`, `7d`, `14d`, `30d`, `45d`, `90d`. Only Android apps collected within this time window will be included in the export.
    * `display_name`: A search string.

Use this endpoint to trigger an Android apps export task. The result of this task will be a spreadsheet.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"display_name": "Chrome"}' \
  https://zentral.example.com/api/inventory/android_apps/export/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

### `/api/inventory/deb_packages/export/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.view_debpackage`
* optional parameters:
    * `export_format`: `csv` or `xlsx`. Defaults to `xlsx`.
    * `source`: The ID of an inventory source. Only Debian packages collected via this source will be included in the export.
    * `last_seen`: `1d`, `7d`, `14d`, `30d`, `45d`, `90d`. Only Debian packages collected within this time window will be included in the export.
    * `name`: A search string.

Use this endpoint to trigger a Debian packages export task. The result of this task will be a spreadsheet.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "Firefox", "last_seen": "90d"}' \
  https://zentral.example.com/api/inventory/deb_packages/export/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a9243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a9243fddd3/"
}
```

### `/api/inventory/ios_apps/export/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.view_iosapp`
* optional parameters:
    * `export_format`: `csv` or `xlsx`. Defaults to `xlsx`.
    * `source`: The ID of an inventory source. Only iOS apps collected via this source will be included in the export.
    * `last_seen`: `1d`, `7d`, `14d`, `30d`, `45d`, `90d`. Only iOS apps collected within this time window will be included in the export.
    * `name`: A search string.

Use this endpoint to trigger an iOS apps export task. The result of this task will be a spreadsheet.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "1Password", "last_seen": "1d"}' \
  https://zentral.example.com/api/inventory/ios_apps/export/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-83a9243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-83a9243fddd3/"
}
```

### `/api/inventory/macos_apps/export/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.view_osxapp`
    * `inventory.view_osxappinstance`
* optional parameters:
    * `export_format`: `csv` or `xlsx`. Defaults to `xlsx`.
    * `source`: The ID of an inventory source. Only macOS apps collected via this source will be included in the export.
    * `last_seen`: `1d`, `7d`, `14d`, `30d`, `45d`, `90d`. Only macOS apps collected within this time window will be included in the export.
    * `bundle_name`: A search string.

Use this endpoint to trigger a macOS apps export task. The result of this task will be a spreadsheet.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"bundle_name": "1Password", "last_seen": "14d", "source": 4641}' \
  https://zentral.example.com/api/inventory/macos_apps/export/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "c1512b8d-1e17-4181-a1c3-83a9243fddd3",
  "task_result_url": "/api/task_result/c1512b8d-1e17-4181-a1c3-83a9243fddd3/"
}
```

### `/api/inventory/programs/export/`

* method: POST
* Content-Type: application/json
* required permission:
    * `inventory.view_program`
    * `inventory.view_programinstance`
* optional parameters:
    * `export_format`: `csv` or `xlsx`. Defaults to `xlsx`.
    * `source`: The ID of an inventory source. Only Windows programs collected via this source will be included in the export.
    * `last_seen`: `1d`, `7d`, `14d`, `30d`, `45d`, `90d`. Only Windows programs collected within this time window will be included in the export.
    * `name`: A search string.

Use this endpoint to trigger a Windows programs export task. The result of this task will be a spreadsheet.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "1Password", "export_format": "csv"}' \
  https://zentral.example.com/api/inventory/programs/export/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "c2512b8d-1e17-4181-a1c3-83a9243fddd3",
  "task_result_url": "/api/task_result/c2512b8d-1e17-4181-a1c3-83a9243fddd3/"
}
```

### `/api/inventory/machines/export_android_apps/`

* method: POST
* required permission:
	* `inventory.view_androidapp`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machines with Android apps collected via this source will be included in the export.

Use this endpoint to trigger a machine Android apps export task. The result of this task will be a Zip archive containing a CSV file for each source.

Example of an export limited to the `Workspace ONE` source:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/inventory/machines/export_android_apps/?source_name=Workspace%20ONE" \
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```
### `/api/inventory/machines/export_deb_packages/`

* method: POST
* required permission:
	* `inventory.view_debpackage`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machines with Debian packages collected via this source will be included in the export.

Use this endpoint to trigger a machine Debian packages export task. The result of this task will be a Zip archive containing a CSV file for each source.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/machines/export_deb_packages/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

### `/api/inventory/machines/export_ios_apps/`

* method: POST
* required permission:
	* `inventory.view_iosapp`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machines with iOS apps collected via this source will be included in the export.

Use this endpoint to trigger a machine iOS apps export task. The result of this task will be a Zip archive containing a CSV file for each source.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/machines/export_ios_apps/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

### `/api/inventory/machines/export_macos_app_instances/`

* method: POST
* required permissions:
	* `inventory.view_osxapp`
	* `inventory.view_osxappinstance`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machines with macOS apps collected via this source will be included in the export.

Use this endpoint to trigger a machine macOS app instances export task. The result of this task will be a Zip archive containing a CSV file for each source.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/machines/export_macos_app_instances/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

### `/api/inventory/machines/export_program_instances/`

* method: POST
* required permissions:
	* `inventory.view_program`
	* `inventory.view_programinstance`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machines with Windows programs collected via this source will be included in the export.

Use this endpoint to trigger a machine Windows program instances export task. The result of this task will be a Zip archive containing a CSV file for each source.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/machines/export_program_instances/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

### `/api/inventory/machines/export_snapshots/`

* method: POST
* required permissions:
	* `inventory.view_machinesnapshot`
* optional parameter:
	* `source_name`: The name of an inventory source. Only machine snapshots collected via this source will be included in the export.

Use this endpoint to trigger a machine snapshots export task. The result of this task will be a Zip archive containing a JSONL file for each source.

Example:

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/inventory/machines/export_snapshots/\
  |python3 -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```
