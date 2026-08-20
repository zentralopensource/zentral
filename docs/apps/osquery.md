# Osquery

[Osquery](https://osquery.readthedocs.io/en/latest/) is an operating system instrumentation framework for Windows, OS X (macOS), Linux, and FreeBSD. Zentral can act as a [remote server](https://osquery.readthedocs.io/en/latest/deployment/remote/#remote-server-api) for Osquery, for configuration, query runs, file carvings, and log collection.

## Zentral configuration

To activate the osquery module, you need to add a `zentral.contrib.osquery` section to the `apps` section in `base.json`.

## HTTP API

### Requests

#### Authentication

API requests are authenticated using a token in the `Authorization` HTTP header:

```
Authorization: Token the_token_string
```

See [API authentication](core.md#api-authentication) for how to create a service account, issue a token for it and set an expiry.

#### Content type

Zentral will parse the body of the request based on the `Content-Type` HTTP header:

* `Content-Type: application/json`
* `Content-Type: application/x-osquery-conf`
* `Content-Type: application/yaml`

### /api/osquery/atcs/

Terraform resource: [`zentral_osquery_atc`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_atc)  
Terraform data source: [`zentral_osquery_atc`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_atc)

#### List all ATCs.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewAutomaticTableConstruction"`
* Optional filter parameter:
    * `name`: name of the ATC.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/atcs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/atcs/?name=Santa+rules" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "name": "Santa rules",
        "description": "Access the Google Santa rules.db",
        "table_name": "santa_rules",
        "query": "SELECT * FROM rules;",
        "path": "/var/db/santa/rules.db",
        "columns": [
            "identifier",
            "state",
            "type",
            "custommsg",
            "timestamp"
        ],
        "platforms": [
            "darwin"
        ],
        "created_at": "2023-01-30T09:39:35.965003",
        "updated_at": "2023-01-30T09:39:35.965011"
    }
]
```

#### Add a new ATC.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createAutomaticTableConstruction"`

Example:

atc.json

```json
{
	"name": "Access example",
	"description": "Access the example example.db",
	"table_name": "example_table",
	"query": "SELECT * FROM example;",
	"path": "/var/db/example/example.db",
	"columns": [
		"one",
		"two",
		"three"
	],
	"platforms": [
		"darwin",
        "linux"
	]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/atcs/" \
  -d @atc.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Access example",
    "description": "Access the example example.db",
    "table_name": "example_table",
    "query": "SELECT * FROM example;",
    "path": "/var/db/example/example.db",
    "columns": [
        "one",
        "two",
        "three"
    ],
    "platforms": [
        "darwin",
        "linux"
    ],
    "created_at": "2023-01-31T08:59:14.097316",
    "updated_at": "2023-01-31T08:59:14.097333"
}
```

### /api/osquery/atcs/`<int:pk>`/

#### Get a ATC.

method: GET
Content-Type: application/json
PBAC action: `Osquery::Action::"viewAutomaticTableConstruction"`
`<int:pk>`: the primary key of the ATC.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/atcs/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Access example",
    "description": "Access the example example.db",
    "table_name": "example_table",
    "query": "SELECT * FROM example;",
    "path": "/var/db/example/example.db",
    "columns": [
        "one",
        "two",
        "three"
    ],
    "platforms": [
        "darwin",
        "linux"
    ],
    "created_at": "2023-01-31T08:59:14.097316",
    "updated_at": "2023-01-31T08:59:14.097333"
}
```

#### Update a ATC.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateAutomaticTableConstruction"`
* `<int:pk>`: the primary key of the ATC.

Example

atc_update.json

```json
{
	"name": "Access example",
	"description": "Access the example example.db on all platforms",
	"table_name": "example_table",
	"query": "SELECT * FROM example;",
	"path": "/var/db/example/example.db",
	"columns": [
		"one",
		"two",
		"three",
		"four"
	],
	"platforms": [
		"darwin",
        "linux",
        "windows",
        "freebsd"
	]
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/atcs/2/" \
  -d @atc_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Access example",
    "description": "Access the example example.db on all platforms",
    "table_name": "example_table",
    "query": "SELECT * FROM example;",
    "path": "/var/db/example/example.db",
    "columns": [
        "one",
        "two",
        "three",
        "four"
    ],
    "platforms": [
        "darwin",
        "linux",
        "windows",
        "freebsd"
    ],
    "created_at": "2023-01-31T08:59:14.097316",
    "updated_at": "2023-01-31T09:05:08.326755"
}
```

#### Delete a ATC.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteAutomaticTableConstruction"`
* `<int:pk>`: the primary key of the ATC.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/atcs/2/" 
```

Response (204 No Content)

### /api/osquery/configurations/

Terraform resource: [`zentral_osquery_configuration`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_configuration)  
Terraform data source: [`zentral_osquery_configuration`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_configuration)

#### List all Configurations.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewConfiguration"`
* Optional filter parameter:
    * `name`: Name of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configurations/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configurations/?name=example" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "name": "example",
        "description": "",
        "inventory": true,
        "inventory_apps": true,
        "inventory_ec2": false,
        "inventory_interval": 600,
        "options": {
            "config_refresh": 120
        },
        "created_at": "2023-01-06T13:05:02.535763",
        "updated_at": "2023-01-30T09:40:23.912582",
        "file_categories": [],
        "automatic_table_constructions": [
            1
        ]
    }
]
```

#### Add a new Configuration.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createConfiguration"`
* Required fields:
    * `name`: Name of the configuration.

Example:

configuration.json

```json
{
	"name": "example2",
	"description": "description of example2",
	"inventory": true,
	"inventory_apps": true,
	"inventory_ec2": false,
	"inventory_interval": 600,
	"options": {
		"config_refresh": 120
	},
	"file_categories": [
		1
	],
	"automatic_table_constructions": [
		1
	]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configurations/" \
  -d @configuration.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2",
    "description": "description of example2",
    "inventory": true,
    "inventory_apps": true,
    "inventory_ec2": false,
    "inventory_interval": 600,
    "options": {
        "config_refresh": 120
    },
    "created_at": "2023-02-01T11:37:00.622052",
    "updated_at": "2023-02-01T11:37:00.622077",
    "file_categories": [
        1
    ],
    "automatic_table_constructions": [
        1
    ]
}
```

### /api/osquery/configurations/`<int:pk>`/

#### Get a Configuration.

method: GET
Content-Type: application/json
PBAC action: `Osquery::Action::"viewConfiguration"`
`<int:pk>`: The primary key of the configuration.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configurations/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2",
    "description": "description of example2",
    "inventory": true,
    "inventory_apps": true,
    "inventory_ec2": false,
    "inventory_interval": 600,
    "options": {
        "config_refresh": 120
    },
    "created_at": "2023-02-01T11:37:00.622052",
    "updated_at": "2023-02-01T11:37:00.622077",
    "file_categories": [
        1
    ],
    "automatic_table_constructions": [
        1
    ]
}
```

#### Update a Configuration.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateConfiguration"`
* `<int:pk>`: The primary key of the configuration.
* Required fields:
    * `name`: Name of the configuration.

Example

configuration_update.json

```json
{
	"name": "example2",
	"description": "description of example2 updated",
	"inventory": true,
	"inventory_apps": true,
	"inventory_ec2": false,
	"inventory_interval": 800,
	"options": {
		"config_refresh": 120
	},
	"file_categories": [],
	"automatic_table_constructions": []
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configurations/2/" \
  -d @configuration_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2",
    "description": "description of example2 updated",
    "inventory": true,
    "inventory_apps": true,
    "inventory_ec2": false,
    "inventory_interval": 800,
    "options": {
        "config_refresh": 120
    },
    "created_at": "2023-02-01T11:37:00.622052",
    "updated_at": "2023-02-01T11:39:12.664992",
    "file_categories": [],
    "automatic_table_constructions": []
}
```

#### Delete a Configuration.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteConfiguration"`
* `<int:pk>`: The primary key of the configuration.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/configurations/2/" 
```

Response (204 No Content)

### /api/osquery/configuration_packs/

Terraform resource: [`zentral_osquery_configuration_pack`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_configuration_pack)

#### List all Configuration Packs.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewConfigurationPack"`
* Optional filter parameter:
    * `pack_id`: primary key of the pack.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/?pack_id=2" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "configuration": 2,
        "pack": 2,
        "tags": [
            1
        ]
    }
]
```

#### Add a new Configuration Pack.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createConfigurationPack"`
* Required fields:
    * `pack`: primary key of an existing pack.
    * `configuration`: primary key of an existing configuration.
* Optional fields:
    * `tags`: list of primary keys of existing tags.

Example:

configurationpack.json

```json
{
	"configuration": 1,
	"pack": 2,
	"tags": [
		2
	]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/" \
  -d @configurationpack.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "configuration": 1,
    "pack": 2,
    "tags": [
        2
    ]
}
```

### /api/osquery/configuration_packs/`<int:pk>`/

#### Get a Configuration Pack.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewConfigurationPack"`
* `<int:pk>`: The primary key of the configuration pack.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "configuration": 1,
    "pack": 2,
    "tags": [
        2
    ]
}
```

#### Update a Configuration Pack.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateConfigurationPack"`
* `<int:pk>`: The primary key of the configurationpack.
* Required fields:
    * `pack`: primary key of an existing pack.
    * `configuration`: primary key of an existing configuration.
* Optional fields:
    * `tags`: list of primary keys of existing tags.

Example

configurationpack_update.json

```json
{
	"configuration": 1,
	"pack": 1,
	"tags": [
		1
	]
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/2/" \
  -d @configurationpack_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "configuration": 1,
    "pack": 1,
    "tags": [
        1
    ]
}
```

#### Delete a Configuration Pack.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteConfigurationPack"`
* `<int:pk>`: The primary key of the configuration pack.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/configuration_packs/2/" 
```

Response (204 No Content)

### /api/osquery/enrollments/

Terraform resource: [`zentral_osquery_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_enrollment)  
Terraform data source: [`zentral_osquery_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_enrollment)

An enrollment ties an Osquery configuration to a [meta business unit](inventory.md) and, optionally, to tags and enrollment restrictions. Its secret is baked into the packages and scripts the three download endpoints below produce.

|Attribute|Description|
|---|---|
|`configuration`|Required. The primary key of the Osquery configuration.|
|`osquery_release`|Optional. The Osquery release to install, for the enrollment packages that bundle one. Blank to install none.|
|`secret.meta_business_unit`|Required. The primary key of the meta business unit the machines are assigned to at enrollment.|
|`secret.tags`|Optional. The tags the machines get at enrollment.|
|`secret.serial_numbers`, `secret.udids`|Optional. Restrict the enrollment to these machines. Blank means any machine.|
|`secret.quota`|Optional. Maximum number of enrollments. Blank means no limit.|

`version`, `enrolled_machines_count`, the three `*_download_url` attributes and `secret.secret` are read only.

#### List all enrollments.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewEnrollment"`

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/enrollments/" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "configuration": 1,
        "osquery_release": "5.12.1",
        "secret": {
            "id": 5,
            "secret": "z1DRxu4HJaN9mI4H5u097McsM2XqLSzvwtmDn2tx3PVUoTVBu6cZXDUdDJPWJbAD",
            "meta_business_unit": 6,
            "tags": [],
            "serial_numbers": [
                "012345678"
            ],
            "udids": null,
            "quota": 10,
            "request_count": 0
        },
        "version": 1,
        "enrolled_machines_count": 0,
        "package_download_url": "https://zentral.example.com/api/osquery/enrollments/1/package/",
        "powershell_script_download_url": "https://zentral.example.com/api/osquery/enrollments/1/powershell_script/",
        "script_download_url": "https://zentral.example.com/api/osquery/enrollments/1/script/",
        "created_at": "2026-08-20T13:08:24.788735",
        "updated_at": "2026-08-20T13:08:24.788737"
    }
]
```

#### Add a new enrollment.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createEnrollment"`

Example:

enrollment.json

```json
{
  "configuration": 1,
  "osquery_release": "5.12.1",
  "secret": {
    "meta_business_unit": 6,
    "quota": 10,
    "serial_numbers": ["012345678"]
  }
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/enrollments/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

Response (201 Created):

```json
{
    "id": 1,
    "configuration": 1,
    "osquery_release": "5.12.1",
    "secret": {
        "id": 5,
        "secret": "z1DRxu4HJaN9mI4H5u097McsM2XqLSzvwtmDn2tx3PVUoTVBu6cZXDUdDJPWJbAD",
        "meta_business_unit": 6,
        "tags": [],
        "serial_numbers": [
            "012345678"
        ],
        "udids": null,
        "quota": 10,
        "request_count": 0
    },
    "version": 1,
    "enrolled_machines_count": 0,
    "package_download_url": "https://zentral.example.com/api/osquery/enrollments/1/package/",
    "powershell_script_download_url": "https://zentral.example.com/api/osquery/enrollments/1/powershell_script/",
    "script_download_url": "https://zentral.example.com/api/osquery/enrollments/1/script/",
    "created_at": "2026-08-20T13:08:24.788735",
    "updated_at": "2026-08-20T13:08:24.788737"
}
```

### /api/osquery/enrollments/`<int:pk>`/

#### Get an enrollment.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/" \
  |python3 -m json.tool
```

#### Update an enrollment.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

Updating an enrollment bumps its version, and the download endpoints below start serving the new artifacts. The secret itself is unchanged.

Example:

enrollment.json

```json
{
  "configuration": 1,
  "osquery_release": "5.12.1",
  "secret": {
    "meta_business_unit": 6,
    "quota": 20,
    "serial_numbers": ["012345678"]
  }
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

#### Delete an enrollment.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

An enrollment owned by a distributor — a [monolith](monolith.md) manifest enrollment package, for instance — cannot be deleted here; it is managed by that distributor. Enrolled machines do **not** block the deletion.

Example:

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/"
```

Response (204 No Content)

### /api/osquery/enrollments/`<int:pk>`/package/

The [`zentral_osquery_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_enrollment) Terraform resource exposes this URL as its read-only `package_url` attribute.

#### Download the macOS enrollment package.

* method: GET
* PBAC action: `Osquery::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

A macOS installer package that configures the Osquery agent and, when `osquery_release` is set, installs that release. This endpoint honours conditional requests — an `If-None-Match` or `If-Modified-Since` matching the current version gets a `304`.

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/package/" \
  --output zentral_osquery_enroll.pkg
```

### /api/osquery/enrollments/`<int:pk>`/script/

The [`zentral_osquery_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_enrollment) Terraform resource exposes this URL as its read-only `script_url` attribute.

#### Download the Linux enrollment script.

* method: GET
* PBAC action: `Osquery::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

A bash script that configures the Osquery agent on Linux.

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/script/" \
  --output zentral_osquery_setup.sh
```

### /api/osquery/enrollments/`<int:pk>`/powershell_script/

The [`zentral_osquery_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_enrollment) Terraform resource exposes this URL as its read-only `powershell_script_url` attribute.

#### Download the Windows enrollment script.

* method: GET
* PBAC action: `Osquery::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

A PowerShell script that configures the Osquery agent on Windows.

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/enrollments/1/powershell_script/" \
  --output zentral_osquery_setup.ps1
```

### /api/osquery/file_categories/

Terraform resource: [`zentral_osquery_file_category`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_file_category)  
Terraform data source: [`zentral_osquery_file_category`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_file_category)

#### List all FileCategories.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewFileCategory"`
* Optional filter parameter:
	* `name`: name of the FileCategory.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/file_categories/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/file_categories/?name=example" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "name": "example",
        "slug": "example",
        "description": "example description",
        "file_paths": [],
        "exclude_paths": [],
        "file_paths_queries": [],
        "access_monitoring": false,
        "created_at": "2023-01-31T11:48:53.014319",
        "updated_at": "2023-01-31T11:48:53.014332"
    }
]
```

#### Add a new FileCategory.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createFileCategory"`

Example:

file_category.json

```json
{
	"name": "example2",
	"slug": "example2",
	"description": "example2 description",
	"file_paths": ["/usr/example2"],
	"exclude_paths": ["/home/you/exclude1", "/home/me/exclude2"],
	"file_paths_queries": [],
	"access_monitoring": true
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/file_categories/" \
  -d @file_category.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2",
    "slug": "example2",
    "description": "example2 description",
    "file_paths": [
        "/usr/example2"
    ],
    "exclude_paths": [
        "/home/you/exclude1",
        "/home/me/exclude2"
    ],
    "file_paths_queries": [],
    "access_monitoring": true,
    "created_at": "2023-01-31T14:09:46.079654",
    "updated_at": "2023-01-31T14:09:46.079664"
}
```

### /api/osquery/file_categories/`<int:pk>`/

#### Get a FileCategory.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewFileCategory"`
* `<int:pk>`: the primary key of the FileCategory.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/file_categories/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2",
    "slug": "example2",
    "description": "example2 description",
    "file_paths": [
        "/usr/example2"
    ],
    "exclude_paths": [
        "/home/you/exclude1",
        "/home/me/exclude2"
    ],
    "file_paths_queries": [],
    "access_monitoring": true,
    "created_at": "2023-01-31T14:09:46.079654",
    "updated_at": "2023-01-31T14:09:46.079664"
}
```

#### Update a FileCategory.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateFileCategory"`
* `<int:pk>`: the primary key of the FileCategory.

Example

file_category_update.json

```json
{
    "name": "example2 updated",
    "description": "example2 description updated",
    "file_paths": [
        "/usr/bin/example2"
    ],
    "exclude_paths": [
        "/home/you/exclude1"
    ],
    "file_paths_queries": [],
    "access_monitoring": false
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/file_categories/2/" \
  -d @file_categories_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "example2 updated",
    "slug": "example2-updated",
    "description": "example2 description updated",
    "file_paths": [
        "/usr/bin/example2"
    ],
    "exclude_paths": [
        "/home/you/exclude1"
    ],
    "file_paths_queries": [],
    "access_monitoring": false,
    "created_at": "2023-01-31T11:48:53.014319",
    "updated_at": "2023-01-31T14:13:39.306239"
}
```

#### Delete a FileCategory.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteFileCategory"`
* `<int:pk>`: the primary key of the FileCategory.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/file_categories/2/" 
```

Response (204 No Content)

### /api/osquery/packs/

Terraform resource: [`zentral_osquery_pack`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_pack)  
Terraform data source: [`zentral_osquery_pack`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_pack)

#### List all Packs.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewPack"`
* Optional filter parameter:
    * `name`: Name of the pack.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/packs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/packs/?name=Default" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "name": "Default",
        "slug": "default",
        "description": "",
        "discovery_queries": [],
        "shard": null,
        "event_routing_key": "",
        "created_at": "2023-01-13T07:06:51.000733",
        "updated_at": "2023-01-13T07:06:51.000743"
    }
]
```

#### Add a new Pack.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createPack"`
* Required fields:
    * `name`: Name of the pack.

Example:

pack.json

```json
{
	"name": "Example",
	"description": "description of the example",
	"discovery_queries": ["SELECT 1 FROM users WHERE username like 'www%';"],
	"shard": 50
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/packs/" \
  -d @pack.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Example",
    "slug": "example",
    "description": "description of the example",
    "discovery_queries": [
        "SELECT 1 FROM users WHERE username like 'www%';"
    ],
    "shard": 50,
    "event_routing_key": "",
    "created_at": "2023-02-02T07:30:42.133421",
    "updated_at": "2023-02-02T07:30:42.133434"
}
```

### /api/osquery/packs/`<int:pk>`/

#### Get a Pack.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewPack"`
* `<int:pk>`: The primary key of the pack.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/packs/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Example",
    "slug": "example",
    "description": "description of the example",
    "discovery_queries": [
        "SELECT 1 FROM users WHERE username like 'www%';"
    ],
    "shard": 50,
    "event_routing_key": "",
    "created_at": "2023-02-02T07:30:42.133421",
    "updated_at": "2023-02-02T07:30:42.133434"
}
```

#### Update a Pack.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updatePack"`
* `<int:pk>`: The primary key of the pack.
* Required fields:
    * `name`: Name of the pack.

Example

pack_update.json

```json
{
	"name": "Example Updated",
	"description": "description of the example updated",
	"discovery_queries": ["SELECT 1 FROM users WHERE username like 'www%';"],
	"shard": 30
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/osquery/packs/2/" \
  -d @pack_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "name": "Example Updated",
    "slug": "example-updated",
    "description": "description of the example updated",
    "discovery_queries": [
        "SELECT 1 FROM users WHERE username like 'www%';"
    ],
    "shard": 30,
    "event_routing_key": "",
    "created_at": "2023-02-02T07:30:42.133421",
    "updated_at": "2023-02-02T07:32:55.258776"
}
```

#### Delete a Pack.

* method: DELETE
* PBAC action: `Osquery::Action::"deletePack"`
* `<int:pk>`: The primary key of the pack.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/packs/2/" 
```

Response (204 No Content)

### /api/osquery/packs/`<slug:slug>`/

#### Create or update a standard Osquery pack.

* method: `PUT`, `DELETE`

This endpoint is designed to create or update a standard Osquery pack.

Examples

pack.json

```json
{
  "name": "First pack",
  "platform": "darwin",
  "queries": {
    "Leverage-A_1": {
      "query" : "select * from launchd where path like '%UserEvent.System.plist';",
      "interval" : "3600",
      "version": "1.4.5",
      "description" : "(http://www.intego.com/mac-security-blog/new-mac-trojan-discovered-related-to-syria/)",
      "value" : "Artifact used by this malware"
    },
    "Leverage-A_2": {
      "query" : "select * from file where path = '/Users/Shared/UserEvent.app';",
      "interval" : "3600",
      "version": "1.4.5",
      "description" : "(http://www.intego.com/mac-security-blog/new-mac-trojan-discovered-related-to-syria/)",
      "value" : "Artifact used by this malware"
    }
  }
}
```

`PUT` the pack.json file to Zentral:

```bash
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @pack.json \
  "https://$ZTL_FQDN/api/osquery/packs/first-pack-slug/" \
  |python3 -m json.tool
```

You should get a response close to this one:

```json
{
  "pack": {
    "pk": 1,
    "slug": "first-pack-slug"
  },
  "result": "created",
  "query_results": {
    "created": 2,
    "deleted": 0,
    "present": 0,
    "updated": 0
  }
}
```

If you `PUT` the same file again, you will get this answer:

```json
{
  "pack": {
    "pk": 1,
    "slug": "first-pack-slug"
  },
  "result": "present",
  "query_results": {
    "created": 0,
    "deleted": 0,
    "present": 2,
    "updated": 0
  }
}
```

If you make a `DELETE` request on the same URL, the pack and all its rules will be deleted:


```bash
$ curl -XDELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  "https://$ZTL_FQDN/api/osquery/packs/first-pack-slug/" \
  |python3 -m json.tool
```

You should get a response close to this one:

```json
{
  "pack": {
    "pk": 1,
    "slug": "first-pack-slug"
  },
  "result": "deleted",
  "query_results": {
    "created": 0,
    "deleted": 2,
    "present": 0,
    "updated": 0
  }
}
```

If the pack is in the osquery format (broken JSON), with line-wrapping characters, or comments, use the `application/x-osquery-conf` content type.

pack.conf  ([Real examples](https://github.com/osquery/osquery/blob/master/packs/) are available in the osquery repository.)

```json
{
  // Do not use this query in production!!!
  "platform": "darwin",
  "queries": {
    "WireLurker": {
      "query" : "select * from launchd where \
        name = 'com.apple.periodic-dd-mm-yy.plist';",
      "interval" : "3600",
      "version": "1.4.5",
      "description" : "(https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)",
      "value" : "Artifact used by this malware - 🔥"
      # 🧨
    }
  }
}
```

```bash
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/x-osquery-conf' \
  --data-binary @pack.conf \
  "https://$ZTL_FQDN/api/osquery/packs/second-pack-slug/" \
  |python3 -m json.tool
```

You should get a response close to this one:

```json
{
  "pack": {
    "pk": 2,
    "slug": "second-pack-slug"
  },
  "result": "created",
  "query_results": {
    "created": 1,
    "deleted": 0,
    "present": 0,
    "updated": 0
  }
}
```

You can also use a YAML payload, with the `application/yaml` content type.

pack.yml

```yaml
---
# Do not use this query in production!!!

platform: "darwin"
queries:
  WireLurker:
    query: >-
      select * from launchd where
      name = 'com.apple.periodic-dd-mm-yy.plist';
    interval: 3600
    version: 1.4.5
    description: (https://github.com/PaloAltoNetworks-BD/WireLurkerDetector)
    value: Artifact used by this malware - 🔥
```

```bash
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/yaml' \
  --data-binary @pack.yml \
  "https://$ZTL_FQDN/api/osquery/packs/second-pack-slug/" \
  |python3 -m json.tool
```

You should get a response close to this one:

```json
{
  "pack": {
    "pk": 2,
    "slug": "third-pack-slug"
  },
  "result": "present",
  "query_results": {
    "created": 0,
    "deleted": 0,
    "present": 0,
    "updated": 1
  }
}
```

### /api/osquery/queries/

Terraform resource: [`zentral_osquery_query`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/osquery_query)  
Terraform data source: [`zentral_osquery_query`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/osquery_query)

#### List all queries.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewQuery"`
* Optional filter parameter:
    * `name`: name of the query.

Examples

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/queries/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/queries/?name=GetApps" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "compliance_check_enabled": false,
        "compliance_check_id": null,
        "name": "GetApps",
        "sql": "SELECT * FROM apps;",
        "platforms": [],
        "scheduling": null,
        "minimum_osquery_version": null,
        "description": "Get list of Apps",
        "value": "",
        "version": 2,
        "created_at": "2023-01-13T07:10:12.571288",
        "updated_at": "2023-01-13T09:24:39.779067"
    }
]
```

#### Add a new query.

* method: POST
* Content-Type: application/json
* PBAC action: `Osquery::Action::"createQuery"`

> **_NOTE:_** `compliance_check_enabled: true` only possible if sql query contains `ztl_status`.

Example

query.json

```json
{
	"compliance_check_enabled": false,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;",
    "scheduling": {
        "pack": 17,
        "interval": 120
    }
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @query.json \
  "https://$ZTL_FQDN/api/osquery/queries/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"compliance_check_id": null,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;",
	"platforms": [],
    "scheduling": {
        "can_be_denylisted": true,
        "interval": 120,
        "log_removed_actions": true,
        "pack": 17,
        "shard": null,
        "snapshot_mode": false
    },
	"minimum_osquery_version": null,
	"description": "Get list of Apps",
	"value": "",
	"version": 1,
	"created_at": "2023-01-13T07:10:12.571288",
	"updated_at": "2023-01-13T09:24:39.779067"
}
```

### /api/osquery/queries/`<int:pk>`/

#### Get a query.

* method: GET
* Content-Type: application/json
* PBAC action: `Osquery::Action::"viewQuery"`
* `<int:pk>`: the primary key of the query.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/queries/1/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"compliance_check_id": null,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;",
	"platforms": [],
    "scheduling": null,
	"minimum_osquery_version": null,
	"description": "Get list of Apps",
	"value": "",
	"version": 1,
	"created_at": "2023-01-13T07:10:12.571288",
	"updated_at": "2023-01-13T09:24:39.779067"
}
```

#### Update a query.

* method: PUT
* Content-Type: application/json
* PBAC action: `Osquery::Action::"updateQuery"`
* `<int:pk>`: the primary key of the query.

Example

query_update.json

```json
{
	"name": "GetUsers",
	"sql": "SELECT * FROM users;"
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @query_update.json \
  "https://$ZTL_FQDN/api/osquery/queries/1/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"compliance_check_id": null,
	"name": "GetUsers",
	"sql": "SELECT * FROM users;",
	"platforms": [],
    "scheduling": null,
	"minimum_osquery_version": null,
	"description": "Get list of Apps",
	"value": "",
	"version": 2,
	"created_at": "2023-01-14T07:10:12.571288",
	"updated_at": "2023-01-14T09:24:39.779067"
}
```

#### Delete a query.

* method: DELETE
* PBAC action: `Osquery::Action::"deleteQuery"`
* `<int:pk>`: the primary key of the query.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/queries/1/"
```

Response (204 No Content)

### `/api/osquery/runs/<int:pk>/results/export/`

#### Trigger a Osquery run export task.

* method: POST
* PBAC actions:
    * `Osquery::Action::"viewDistributedQueryResult"`
* optional parameter:
    * `export_format`: One of `csv`, `ndjson` or `json`. Defaults to `csv`.

Use this endpoint to trigger a Osquery run export task. The result of this task will be a file containing all the data collected during the run.

Example

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/osquery/runs/1/results/export/" \
  |python3 -m json.tool
```

Response

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```
