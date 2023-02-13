# Osquery

[Osquery](https://osquery.readthedocs.io/en/latest/) is an operating system instrumentation framework for Windows, OS X (macOS), Linux, and FreeBSD. Zentral can act as a [remote server](https://osquery.readthedocs.io/en/latest/deployment/remote/#remote-server-api) for Osquery, for configuration, query runs, file carvings, and log collection.

## Zentral configuration

To activate the osquery module, you need to add a `zentral.contrib.osquery` section to the `apps` section in `base.json`.

## HTTP API

### Requests

#### Authentication

API requests are authenticated using a token in the `Authorization` HTTP header.

To get a token, you can create a service account. As a superuser, go to Setup > Manage users, and in the "Service accounts" subsection, click on the [Create] button. Pick a name for your service account and [Save]. You will be redirected to a token view. The token is only displayed once. To reveal it, click on the eye icon. Once you have saved it (in a password manager, in a configuration variable, …), you can click on the [OK] button.

You can also add an API token to a normal user, although it is not recommended. To do so, click on the user in the User list, and click on the [+] button next to the API token boolean.

If you have lost or leaked a token, you can delete it by clicking on the user or service account name, and then click on the 🗑 next to the API token boolean.

The format for the `Authorization` header is the following:

```
Authorization: Token the_token_string
```

#### Content type

Zentral will parse the body of the request based on the `Content-Type` HTTP header:

* `Content-Type: application/json`
* `Content-Type: application/x-osquery-conf`
* `Content-Type: application/yaml`

### /api/osquery/atcs/

#### List all ATCs.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_automatictableconstruction`
* Optional filter parameter:
    * `name`: name of the ATC.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/atcs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/atcs/?name=Santa+rules" \
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
* Required permission: `osquery.add_automatictableconstruction`

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
  "https://zentral.example.com/api/osquery/atcs/" \
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
Required permission: `osquery.view_automatictableconstruction`
`<int:pk>`: the primary key of the ATC.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/atcs/2/" \
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
* Required permission: `osquery.update_automatictableconstruction`
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
  "https://zentral.example.com/api/osquery/atcs/2/" \
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
* Required permission: `osquery.delete_automatictableconstruction`
* `<int:pk>`: the primary key of the ATC.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/atcs/2/" 
```

Response (204 No Content)

### /api/osquery/configurations/

#### List all Configurations.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_configuration`
* Optional filter parameter:
    * `name`: Name of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurations/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurations/?name=example" \
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
* Required permission: `osquery.add_configuration`
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
  "https://zentral.example.com/api/osquery/configurations/" \
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
Required permission: `osquery.view_configuration`
`<int:pk>`: The primary key of the configuration.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurations/2/" \
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
* Required permission: `osquery.update_configuration`
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
  "https://zentral.example.com/api/osquery/configurations/2/" \
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
* Required permission: `osquery.delete_configuration`
* `<int:pk>`: The primary key of the configuration.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/configurations/2/" 
```

Response (204 No Content)

### /api/osquery/configurationpacks/

#### List all Configuration Packs.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_configurationpack`
* Optional filter parameter:
    * `pack_id`: primary key of the pack.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurationpacks/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurationpacks/?pack_id=2" \
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
* Required permission: `osquery.add_configurationpack`
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
  "https://zentral.example.com/api/osquery/configurationpacks/" \
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

### /api/osquery/configurationpacks/`<int:pk>`/

#### Get a Configuration Pack.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_configurationpack`
* `<int:pk>`: The primary key of the configuration pack.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/configurationpacks/2/" \
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
* Required permission: `osquery.update_configurationpack`
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
  "https://zentral.example.com/api/osquery/configurationpacks/2/" \
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
* Required permission: `osquery.delete_configurationpack`
* `<int:pk>`: The primary key of the configuration pack.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/configurationpacks/2/" 
```

Response (204 No Content)

### /api/osquery/file_categories/

#### List all FileCategories.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_filecategory`
* Optional filter parameter:
	* `name`: name of the FileCategory.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/file_categories/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/file_categories/?name=example" \
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
* Required permission: `osquery.add_filecategory`

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
  "https://zentral.example.com/api/osquery/file_categories/" \
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
* Required permission: `osquery.view_filecategory`
* `<int:pk>`: the primary key of the FileCategory.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/file_categories/2/" \
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
* Required permission: `osquery.update_filecategory`
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
  "https://zentral.example.com/api/osquery/file_categories/2/" \
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
* Required permission: `osquery.delete_filecategory`
* `<int:pk>`: the primary key of the FileCategory.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/file_categories/2/" 
```

Response (204 No Content)

### /api/osquery/packs/

#### List all Packs.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_pack`
* Optional filter parameter:
    * `name`: Name of the pack.
    * `configuration_id`: primary key of the configuration.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packs/?name=Default" \
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
* Required permission: `osquery.add_pack`
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
  "https://zentral.example.com/api/osquery/packs/" \
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
* Required permission: `osquery.view_pack`
* `<int:pk>`: The primary key of the pack.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packs/2/" \
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
* Required permission: `osquery.update_pack`
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
  "https://zentral.example.com/api/osquery/packs/2/" \
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
* Required permission: `osquery.delete_pack`
* `<int:pk>`: The primary key of the pack.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/packs/2/" 
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
  "https://zentral.example.com/api/osquery/packs/first-pack-slug/" \
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
  "https://zentral.example.com/api/osquery/packs/first-pack-slug/" \
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
  "https://zentral.example.com/api/osquery/packs/second-pack-slug/" \
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
  "https://zentral.example.com/api/osquery/packs/second-pack-slug/" \
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

### /api/osquery/packqueries/

#### List all Pack Queries.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_packquery`
* Optional filter parameter:
    * `pack_id`: primary key of the pack.

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packqueries/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packqueries/?pack_id=2" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "pack": 2,
        "query": 1,
        "slug": "apps2",
        "interval": 60,
        "log_removed_actions": true,
        "snapshot_mode": false,
        "shard": null,
        "can_be_denylisted": false,
        "created_at": "2023-01-18T07:33:49.207023",
        "updated_at": "2023-01-18T07:33:49.207035"
    }
]
```

#### Add a new Pack Query.

* method: POST
* Content-Type: application/json
* Required permission: `osquery.add_packquery`
* Required fields:
    * `pack`: primary key of an existing pack.
    * `query`: primary key of an existing query.
    * `interval`: interval in seconds.

Example:

packquery.json

```json
{
	"pack": 3,
	"query": 3,
	"interval": 120,
	"log_removed_actions": true,
	"snapshot_mode": false,
	"shard": 50,
	"can_be_denylisted": false
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packqueries/" \
  -d @packquery.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "pack": 3,
    "query": 3,
    "slug": "test-3673763",
    "interval": 120,
    "log_removed_actions": true,
    "snapshot_mode": false,
    "shard": 50,
    "can_be_denylisted": false,
    "created_at": "2023-02-03T11:54:19.190120",
    "updated_at": "2023-02-03T11:54:19.190130"
}
```

### /api/osquery/packqueries/`<int:pk>`/

#### Get a Pack Query.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_packquery`
* `<int:pk>`: The primary key of the packquery.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packqueries/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "pack": 3,
    "query": 3,
    "slug": "test-3673763",
    "interval": 120,
    "log_removed_actions": true,
    "snapshot_mode": false,
    "shard": 50,
    "can_be_denylisted": false,
    "created_at": "2023-02-03T11:54:19.190120",
    "updated_at": "2023-02-03T11:54:19.190130"
}
```

#### Update a Pack Query.

* method: PUT
* Content-Type: application/json
* Required permission: `osquery.update_packquery`
* `<int:pk>`: The primary key of the packquery.
* Required fields:
    * `pack`: primary key of an existing pack.
    * `query`: primary key of an existing query.
    * `interval`: interval in seconds.

Example

packquery_update.json

```json
{
	"pack": 3,
	"query": 3,
	"interval": 60,
	"log_removed_actions": false,
	"snapshot_mode": true,
	"shard": 10,
	"can_be_denylisted": false
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/osquery/packqueries/2/" \
  -d @packquery_update.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "pack": 3,
    "query": 3,
    "slug": "test-3673763",
    "interval": 60,
    "log_removed_actions": false,
    "snapshot_mode": true,
    "shard": 10,
    "can_be_denylisted": false,
    "created_at": "2023-02-03T11:54:19.190120",
    "updated_at": "2023-02-03T11:55:55.902529"
}
```

#### Delete a Pack Query.

* method: DELETE
* Required permission: `osquery.delete_packquery`
* `<int:pk>`: The primary key of the packquery.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/packqueries/2/" 
```

Response (204 No Content)

### /api/osquery/queries/

#### List all queries.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_query`
* Optional filter parameter:
    * `name`: name of the query.

Examples

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/queries/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/queries/?name=GetApps" \
  |python3 -m json.tool
```

Response:

```json
[
    {
        "id": 1,
        "compliance_check_enabled": false,
        "name": "GetApps",
        "sql": "SELECT * FROM apps;",
        "platforms": [],
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
* Required permission: `osquery.add_query`

> **_NOTE:_** `compliance_check_enabled: true` only possible if sql query contains `ztl_status`.

Example

query.json

```json
{
	"compliance_check_enabled": false,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;"
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @query.json \
  "https://zentral.example.com/api/osquery/queries/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;",
	"platforms": [],
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
* Required permission: `osquery.view_query`
* `<int:pk>`: the primary key of the query.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/queries/1/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"name": "GetApps",
	"sql": "SELECT * FROM apps;",
	"platforms": [],
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
* Required permission: `osquery.update_query`
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
  "https://zentral.example.com/api/osquery/queries/1/" \
  |python3 -m json.tool
```

Response:

```json
{
	"id": 1,
	"compliance_check_enabled": false,
	"name": "GetUsers",
	"sql": "SELECT * FROM users;",
	"platforms": [],
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
* Required permission: `osquery.delete_query`
* `<int:pk>`: the primary key of the query.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/queries/1/"
```

Response (204 No Content)

### `/api/osquery/runs/<int:pk>/results/export/`

#### Trigger a Osquery run export task.

* method: POST
* required permissions:
    * `osquery.view_distributedqueryresult`
* optional parameter:
    * `export_format`: One of `csv`, `ndjson` or `json`. Defaults to `csv`.

Use this endpoint to trigger a Osquery run export task. The result of this task will be a file containing all the data collected during the run.

Example

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/runs/1/results/export/" \
  |python3 -m json.tool
```

Response

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```
