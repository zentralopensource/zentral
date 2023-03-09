# Munki

[Munki](https://github.com/munki/munki) is a set of tools to manage software installation for macOS. Zentral can act as a reporting server for Munki. Using the [preflight and postflight scripts](https://github.com/munki/munki/wiki/Preflight-And-Postflight-Scripts), it can collect inventory data and Munki events.

## Zentral configuration

To activate the munki module, you need to add a `zentral.contrib.munki` section to the `apps`section in `base.json`.

### `metrics`

**OPTIONAL**

This boolean is used to toggle the munki metrics endpoint. `false` by default. When activated, three different metric families are exported:

* `zentral_munki_active_machines_bucket`  
Number of active machines. Multiple buckets are published, corresponding to the number of days within which the machines reported for the last time. The `le` label (*less than or equal to*) can be used to select each bucket. Available values are  1, 7, 14, 30, 45, 90 (days), and +Inf (*infinity*) for the bucket including all the machines regardless of the time they last reported.
* `zentral_munki_installed_pkginfos_bucket`  
Number of installs for each package. Multiple buckets are published (see above).
* `zentral_munki_failed_pkginfos`   
Number of failed installs for each package.

## HTTP API

### /api/munki/configurations/


#### List all configurations

* method: GET
* required permissions: `munki.view_configuration`
* Optional filter parameter:
    * `name`: name of the configuration

Examples:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/munki/configurations/ \
  |python3 -m json.tool
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/munki/configurations/?name=Default \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "auto_failed_install_incidents": false,
        "auto_reinstall_incidents": true,
        "collected_condition_keys": [
            "arch",
            "machine_type"
        ],
        "created_at": "2021-03-17T10:14:00.493868",
        "description": "",
        "id": 1,
        "inventory_apps_full_info_shard": 100,
        "managed_installs_sync_interval_days": 7,
        "name": "Default",
        "principal_user_detection_domains": [
            "example.com"
        ],
        "principal_user_detection_sources": [
            "logged_in_user"
        ],
        "updated_at": "2022-01-05T09:04:39.201411",
        "version": 5
    }
]
```

#### Add a configuration

* method: POST
* Content-Type: application/json
* Required permission: `munki.add_configuration`

Example:

configuration.json

```json
{
  "name": "Default",
  "description": "Description",
  "inventory_apps_full_info_shard": 50,
  "principal_user_detection_sources": [
    "google_chrome",
    "company_portal"
  ],
  "principal_user_detection_domains": [
    "zentral.io"
  ],
  "collected_condition_keys": [
    "arch",
    "machine_type"
  ],
  "managed_installs_sync_interval_days": 1,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true,
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @configuration.json \
  https://zentral.example.com/api/munki/configurations/ \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 6,
  "name": "Default",
  "description": "Description",
  "inventory_apps_full_info_shard": 50,
  "principal_user_detection_sources": [
    "google_chrome",
    "company_portal"
  ],
  "principal_user_detection_domains": [
    "zentral.io"
  ],
  "collected_condition_keys": [
    "arch",
    "machine_type"
  ],
  "managed_installs_sync_interval_days": 1,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true,
  "created_at": "2022-01-05T09:04:39.201311",
  "updated_at": "2022-01-05T09:04:39.201411"
}
```

### /api/munki/configurations/`<int:pk>`/

#### Get a configuration

* method: GET
* required permission: `munki.view_configuration`
* `<int:pk>`: the primary key of the configuration

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/munki/configurations/6/ \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 6,
  "name": "Default",
  "description": "Description",
  "inventory_apps_full_info_shard": 50,
  "principal_user_detection_sources": [
    "google_chrome",
    "company_portal"
  ],
  "principal_user_detection_domains": [
    "zentral.io"
  ],
  "collected_condition_keys": [
    "arch",
    "machine_type"
  ],
  "managed_installs_sync_interval_days": 1,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true,
  "created_at": "2022-01-05T09:04:39.201311",
  "updated_at": "2022-01-05T09:04:39.201411"
}
```

#### Update a configuration

* method: PUT
* Content-Type: application/json
* Required permission: `munki.change_configuration`
* `<int:pk>`: the primary key of the configuration

Example:

configuration.json

```json
{
  "name": "Default",
  "description": "Description",
  "inventory_apps_full_info_shard": 50,
  "principal_user_detection_sources": [
    "google_chrome",
    "company_portal"
  ],
  "principal_user_detection_domains": [
    "zentral.io"
  ],
  "collected_condition_keys": [
    "arch",
    "machine_type"
  ],
  "managed_installs_sync_interval_days": 1,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true,
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @configuration.json \
  https://zentral.example.com/api/munki/configurations/6/ \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 6,
  "name": "Default",
  "description": "Description",
  "inventory_apps_full_info_shard": 50,
  "principal_user_detection_sources": [
    "google_chrome",
    "company_portal"
  ],
  "principal_user_detection_domains": [
    "zentral.io"
  ],
  "collected_condition_keys": [
    "arch",
    "machine_type"
  ],
  "managed_installs_sync_interval_days": 1,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true,
  "created_at": "2022-01-05T09:04:39.201311",
  "updated_at": "2022-01-05T09:04:39.201411"
}
```

#### Delete a configuration

* method: DELETE
* Required permission: `munki.delete_configuration`
* `<int:pk>`: the primary key of the configuration

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://zentral.example.com/api/munki/configurations/6/
```

Response (204 No Content)

### /api/munki/enrollments/

* method: GET
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to list all available Zentral munki enrollments.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/munki/enrollments/ \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "configuration": 1,
        "created_at": "2020-06-16T14:10:32.322536",
        "enrolled_machines_count": 5,
        "id": 1,
        "package_download_url": "https://zentral.example.com/api/munki/enrollments/1/package/",
        "secret": {
            "id": 11,
            "meta_business_unit": 1,
            "quota": null,
            "request_count": 5,
            "secret": "CtX89oaZJeoXAkEDatwRdDX2y5Ubr3fl9rRUDCtkLFXovdFvFjXz37g4rFm0mQy7",
            "serial_numbers": [],
            "tags": [],
            "udids": []
        },
        "updated_at": "2021-03-17T10:14:00.496743",
        "version": 1
    }
]
```

### /api/munki/enrollments/`<int:pk>`/

* method: GET
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to get a specific Zentral munki enrollment.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/munki/enrollments/1/ \
  |python3 -m json.tool
```

Response:

```json
{
    "configuration": 1,
    "created_at": "2020-06-16T14:10:32.322536",
    "enrolled_machines_count": 5,
    "id": 1,
    "package_download_url": "https://zentral.example.com/api/munki/enrollments/1/package/",
    "secret": {
        "id": 11,
        "meta_business_unit": 1,
        "quota": null,
        "request_count": 5,
        "secret": "CtX89oaZJeoXAkEDatwRdDX2y5Ubr3fl9rRUDCtkLFXovdFvFjXz37g4rFm0mQy7",
        "serial_numbers": [],
        "tags": [],
        "udids": []
    },
    "updated_at": "2021-03-17T10:14:00.496743",
    "version": 1
}
```

### /api/munki/enrollments/`<int:pk>`/package/

* method: GET
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to download a Zentral enrollment package.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o zentral_munki_enrollment_package.pkg \
  https://zentral.example.com/api/munki/enrollments/1/package/
```
