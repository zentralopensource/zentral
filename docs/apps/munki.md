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

### Requests

#### Authentication

API requests are authenticated using a token in the `Authorization` HTTP header:

```
Authorization: Token the_token_string
```

See [API authentication](core.md#api-authentication) for how to create a service account, issue a token for it and set an expiry.

### /api/munki/configurations/


#### List all configurations

* method: GET
* PBAC actions: `Munki::Action::"viewConfiguration"`
* Optional filter parameter:
    * `name`: name of the configuration

Examples:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/configurations/ \
  |python3 -m json.tool
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/munki/configurations/?name=Default" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "name": "Default",
        "description": "",
        "inventory_apps_full_info_shard": 100,
        "principal_user_detection_sources": [
            "logged_in_user"
        ],
        "principal_user_detection_domains": [
            "zentral.io"
        ],
        "collected_condition_keys": [
            "arch",
            "machine_type"
        ],
        "managed_installs_sync_interval_days": 7,
        "script_checks_run_interval_seconds": 86400,
        "auto_reinstall_incidents": true,
        "auto_failed_install_incidents": false,
        "version": 6,
        "created_at": "2021-03-17T10:14:00.493868",
        "updated_at": "2023-02-08T06:57:49.358674"
    }
]
```

#### Add a configuration

* method: POST
* Content-Type: application/json
* PBAC action: `Munki::Action::"createConfiguration"`

Example:

configuration.json

```json
{
  "name": "Not all apps",
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
  "script_checks_run_interval_seconds": 86400,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @configuration.json \
  https://$ZTL_FQDN/api/munki/configurations/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Not all apps",
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
    "script_checks_run_interval_seconds": 86400,
    "auto_reinstall_incidents": true,
    "auto_failed_install_incidents": true,
    "version": 0,
    "created_at": "2023-03-10T07:22:07.939979",
    "updated_at": "2023-03-10T07:22:07.939994"
}
```

### /api/munki/configurations/`<int:pk>`/

#### Get a configuration

* method: GET
* PBAC action: `Munki::Action::"viewConfiguration"`
* `<int:pk>`: the primary key of the configuration

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/configurations/2/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Not all apps",
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
    "script_checks_run_interval_seconds": 86400,
    "auto_reinstall_incidents": true,
    "auto_failed_install_incidents": true,
    "version": 0,
    "created_at": "2023-03-10T07:22:07.939979",
    "updated_at": "2023-03-10T07:22:07.939994"
}
```

#### Update a configuration

* method: PUT
* Content-Type: application/json
* PBAC action: `Munki::Action::"updateConfiguration"`
* `<int:pk>`: the primary key of the configuration

Example:

configuration.json

```json
{
  "name": "Not all apps",
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
  "script_checks_run_interval_seconds": 86400,
  "auto_reinstall_incidents": true,
  "auto_failed_install_incidents": true
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @configuration.json \
  https://$ZTL_FQDN/api/munki/configurations/2/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Not all apps",
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
    "script_checks_run_interval_seconds": 86400,
    "auto_reinstall_incidents": true,
    "auto_failed_install_incidents": true,
    "version": 1,
    "created_at": "2023-03-10T07:22:07.939979",
    "updated_at": "2023-03-10T07:24:17.877120"
}
```

#### Delete a configuration

* method: DELETE
* PBAC action: `Munki::Action::"deleteConfiguration"`
* `<int:pk>`: the primary key of the configuration

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/munki/configurations/6/
```

Response (204 No Content)

### /api/munki/enrollments/

#### List all enrollments

* method: GET
* PBAC action: `Munki::Action::"viewEnrollment"`
* Optional filter parameter:
    * `configuration_id`: primary key of the configuration

Examples:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/enrollments/ \
  |python3 -m json.tool
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/enrollments/?configuration_id=1 \
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
        "package_download_url": "https://$ZTL_FQDN/api/munki/enrollments/1/package/",
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

#### Add an enrollment

* method: POST
* Content-Type: application/json
* PBAC action: `Munki::Action::"createEnrollment"`

Example:

enrollment.json

```json
{
  "configuration": 2,
  "secret": {
    "meta_business_unit": 1,
    "tags": [17, 42]
  }
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/munki/enrollments/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "configuration": 2,
  "enrolled_machines_count": 0,
  "secret": {
    "secret": "AzZhxoWDXDqpUr06O8SQG53eE7fkiOy0U02uOghjQG3zowXMlJqpblSFXvkk05ak",
    "request_count": 0,
    "id": 3,
    "serial_numbers": [],
    "meta_business_unit": 1,
    "quota": null,
    "tags": [17, 42],
    "udids": []
  },
  "version": 1,
  "package_download_url": "https://$ZTL_FQDN/api/munki/enrollments/1/package/",
  "created_at": "2023-01-10T11:02:51.831544",
  "updated_at": "2023-01-10T11:02:51.831553"
}
```

### /api/munki/enrollments/`<int:pk>`/

#### Get an enrollment

* method: GET
* PBAC action: `Munki::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/enrollments/1/ \
  |python3 -m json.tool
```

Response:

```json
{
    "configuration": 1,
    "created_at": "2020-06-16T14:10:32.322536",
    "enrolled_machines_count": 5,
    "id": 1,
    "package_download_url": "https://$ZTL_FQDN/api/munki/enrollments/1/package/",
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

#### Update an enrollment

* method: PUT
* Content-Type: application/json
* PBAC action: `Munki::Action::"updateEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

enrollment.json

```json
{
  "configuration": 2,
  "secret": {
    "meta_business_unit": 1,
    "tags": [17, 42]
  }
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/munki/enrollments/1/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "configuration": 2,
  "enrolled_machines_count": 0,
  "secret": {
    "secret": "AzZhxoWDXDqpUr06O8SQG53eE7fkiOy0U02uOghjQG3zowXMlJqpblSFXvkk05ak",
    "request_count": 0,
    "id": 3,
    "serial_numbers": [],
    "meta_business_unit": 1,
    "quota": null,
    "tags": [17, 42],
    "udids": []
  },
  "version": 2,
  "package_download_url": "https://$ZTL_FQDN/api/munki/enrollments/1/package/",
  "created_at": "2023-01-10T11:02:51.831544",
  "updated_at": "2023-01-10T11:02:51.831553"
}
```

#### Delete an enrollment

* method: DELETE
* PBAC action: `Munki::Action::"deleteEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/munki/enrollments/1/"
```

Response (204 No Content)

### /api/munki/enrollments/`<int:pk>`/package/

#### Download a Zentral enrollment package

* method: GET
* PBAC action: `Munki::Action::"viewEnrollment"`

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o zentral_munki_enrollment_package.pkg \
  https://$ZTL_FQDN/api/munki/enrollments/1/package/
```

### /api/munki/script_checks/

A script check is a script the Munki agent runs on the machines in its scope, at most once every `script_checks_run_interval_seconds` (a [configuration](#apimunkiconfigurations) attribute). It is a [compliance check](inventory.md#compliance-checks): the agent reports the script's output, and Zentral compares it to the expected result to derive the machine's status.

|Attribute|Description|
|---|---|
|`name`|Required, and unique across the Munki script checks. It is the name of the compliance check.|
|`description`|Optional, free text.|
|`type`|`ZSH_STR`, `ZSH_INT` or `ZSH_BOOL` — the type the script's output is compared as. `ZSH_STR` by default.|
|`source`|The zsh script. Its output is compared to `expected_result`.|
|`expected_result`|The value the output must equal for the machine to be compliant. It has to parse as the declared `type` — an integer for `ZSH_INT`, `true`/`false` for `ZSH_BOOL`.|
|`tags`|Run only on the machines carrying any of these tags. Empty means every machine.|
|`excluded_tags`|Never run on the machines carrying any of these tags. Must be disjoint from `tags`.|
|`arch_amd64` / `arch_arm64`|Whether the check runs on Intel, on Apple Silicon, or on both. At least one is required.|
|`min_os_version` / `max_os_version`|The macOS version range the check runs on. Blank for no bound. `max_os_version` is exclusive.|

`version` and `compliance_check_id` are read only.

#### List all script checks

* method: GET
* PBAC action: `Munki::Action::"viewScriptCheck"`
* Optional filter parameter:
    * `name`: name of the script check

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/script_checks/ \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "name": "FileVault enabled",
        "description": "Check that FileVault is on",
        "version": 1,
        "compliance_check_id": 10,
        "id": 1,
        "tags": [
            3
        ],
        "excluded_tags": [
            4
        ],
        "arch_amd64": true,
        "arch_arm64": true,
        "min_os_version": "14",
        "max_os_version": "",
        "type": "ZSH_BOOL",
        "source": "/usr/bin/fdesetup isactive",
        "expected_result": "true",
        "created_at": "2026-08-20T13:03:23.767041",
        "updated_at": "2026-08-20T13:03:23.767043"
    }
]
```

#### Add a script check

* method: POST
* Content-Type: application/json
* PBAC action: `Munki::Action::"createScriptCheck"`

Example:

script_check.json

```json
{
  "name": "FileVault enabled",
  "description": "Check that FileVault is on",
  "type": "ZSH_BOOL",
  "source": "/usr/bin/fdesetup isactive",
  "expected_result": "true",
  "tags": [3],
  "excluded_tags": [4],
  "arch_amd64": true,
  "arch_arm64": true,
  "min_os_version": "14",
  "max_os_version": ""
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @script_check.json \
  https://$ZTL_FQDN/api/munki/script_checks/ \
  |python3 -m json.tool
```

Response:

```json
{
    "name": "FileVault enabled",
    "description": "Check that FileVault is on",
    "version": 1,
    "compliance_check_id": 10,
    "id": 1,
    "tags": [
        3
    ],
    "excluded_tags": [
        4
    ],
    "arch_amd64": true,
    "arch_arm64": true,
    "min_os_version": "14",
    "max_os_version": "",
    "type": "ZSH_BOOL",
    "source": "/usr/bin/fdesetup isactive",
    "expected_result": "true",
    "created_at": "2026-08-20T13:03:23.767041",
    "updated_at": "2026-08-20T13:03:23.767043"
}
```

### /api/munki/script_checks/`<int:pk>`/

#### Get a script check

* method: GET
* PBAC action: `Munki::Action::"viewScriptCheck"`
* `<int:pk>`: the primary key of the script check

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/munki/script_checks/1/ \
  |python3 -m json.tool
```

#### Update a script check

* method: PUT
* Content-Type: application/json
* PBAC action: `Munki::Action::"updateScriptCheck"`
* `<int:pk>`: the primary key of the script check

**Any** change to the check — its source, its expected result, its scope or its compatibility gate — bumps the version, and the machines in scope run it again on their next check-in. This is unlike the [Turbo scripts](turbo.md#apiturboscripts), where only a source change bumps the version.

Example:

script_check.json

```json
{
  "name": "FileVault enabled",
  "description": "Check that FileVault is on",
  "type": "ZSH_BOOL",
  "source": "/usr/bin/fdesetup isactive",
  "expected_result": "true",
  "tags": [3],
  "excluded_tags": [4],
  "arch_amd64": true,
  "arch_arm64": false,
  "min_os_version": "14",
  "max_os_version": ""
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @script_check.json \
  https://$ZTL_FQDN/api/munki/script_checks/1/ \
  |python3 -m json.tool
```

Response:

```json
{
    "name": "FileVault enabled",
    "description": "Check that FileVault is on",
    "version": 2,
    "compliance_check_id": 10,
    "id": 1,
    "tags": [
        3
    ],
    "excluded_tags": [
        4
    ],
    "arch_amd64": true,
    "arch_arm64": false,
    "min_os_version": "14",
    "max_os_version": "",
    "type": "ZSH_BOOL",
    "source": "/usr/bin/fdesetup isactive",
    "expected_result": "true",
    "created_at": "2026-08-20T13:03:23.767041",
    "updated_at": "2026-08-20T13:03:23.786024"
}
```

#### Delete a script check

* method: DELETE
* PBAC action: `Munki::Action::"deleteScriptCheck"`
* `<int:pk>`: the primary key of the script check

Deleting a script check deletes its compliance check and all its machine statuses.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/munki/script_checks/1/
```

Response (204 No Content)
