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

### `/api/munki/configurations/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `munki.view_configuration`

Use this endpoint to list all available Zentral munki configurations.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/munki/configurations/ \
  |python -m json.tool
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

### `/api/munki/configurations/{id}/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `munki.view_configuration`

Use this endpoint to get a specific Zentral munki configuration.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/munki/configurations/1/ \
  |python -m json.tool
```

Response:

```json
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
```

### `/api/munki/enrollments/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to list all available Zentral munki enrollments.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/munki/enrollments/ \
  |python -m json.tool
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

### `/api/munki/enrollments/{id}/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to get a specific Zentral munki enrollment.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/munki/enrollments/1/ \
  |python -m json.tool
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

### `/api/munki/enrollments/{id}/package/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `munki.view_enrollment`

Use this endpoint to download a Zentral enrollment package.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o zentral_munki_enrollment_package.pkg \
  https://zentral.example.com/api/munki/enrollments/1/package/
```
