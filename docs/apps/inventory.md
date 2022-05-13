# Inventory

The Zentral Inventory app is mandatory in a Zentral deployment. It is used to store all the inventory information.

## Zentral configuration

A `zentral.contrib.inventory` subsection must be present in the `apps` section in [the configuration](/configuration).

### `metrics`

**OPTIONAL**

This boolean is used to toggle the inventory metrics endpoint. `false` by default.

### `metrics_options`

**OPTIONAL**

A dictionary to configure the available inventory metrics. Only configured metrics will be published. Empty by default.

Six different metric families are available: `android_apps`, `deb_packages`, `ios_apps`, `osx_apps`, `programs`, and `os_versions`. To publish a metric family, the corresponding configuration dictionary must be set in the `metrics_options` section. For each metric family, a mandatory `sources` attribute must be set, to filter the inventory sources. A mandatory `bundle_ids` attribute (array of strings) must be set in the `osx_apps` metric family configuration to filter the published bundle metrics. For the `android_apps`, `deb_packages`, `ios_apps`, and `programs` metric families, a `names` attribute (array of strings) must be set, respectively to the list of Android app names, Debian package names, iOS app names, or Windows program names to include in the metrics.

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
