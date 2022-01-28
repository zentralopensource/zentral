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

Four different metric families are available: `osx_apps`, `deb_packages`, `programs`, and `os_versions`. To publish a metric family, the corresponding configuration dictionary must be set in the `metrics_options` section. For each metric family, a mandatory `sources` attribute must be set, to filter the inventory sources. A mandatory `bundle_ids` attribute (array of strings) must be set in the `osx_apps` metric family configuration to filter the published bundle metrics. For the `deb_packages` and `programs` metric families, a `names` attribute (array of strings) must be set, respectively to the list of Debian package names or Windows program names to include in the metrics.

Example:

```json
{
  "metrics": true,
  "metrics_options": {
    "osx_apps": {
      "sources": ["Munki", "osquery"],
      "bundle_ids": ["org.mozilla.firefox", "us.zoom.xos"]
    },
    "deb_packages": {
      "sources": ["osquery"],
      "names": ["firefox", "falcon-sensor"]
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

### /api/inventory/machines/archive/

* method: POST
* Content-Type: application/json
* required permissions:
    * `inventory.change_machinesnapshot`

Use this endpoint to archive machines using their serial numbers. The inventory data will be kept in the database, in case the machines show up again, but the machines will not be displayed when browsing or exporting the inventory. Up to 1000 machines can be archived per API call.

Example:

```
$ curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"serial_numbers": ["0123456789"]}' \
  https://zentral.example.com/api/inventory/machines/archive/\
  |python -m json.tool
```

Response:

```json
{"current_machine_snapshots": 0}
```

### /api/inventory/machines/prune/

* method: POST
* Content-Type: application/json
* required permissions:
    * `inventory.delete_machinesnapshot`

Use this endpoint to prune machines using their serial numbers. The inventory data will be removed from the database. Up to 1000 machines can be pruned per API call.

Example:

```
$ curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"serial_numbers": ["0123456789"]}' \
  https://zentral.example.com/api/inventory/machines/prune/\
  |python -m json.tool
```

Response:

```json
{"current_machine_snapshots": 1,
 "machine_snapshots": 2,
 "machine_snapshot_commits": 13}
```
