# Osquery

[Osquery](https://osquery.readthedocs.io/en/latest/) is an operating system instrumentation framework for Windows, OS X (macOS), Linux, and FreeBSD. Zentral can act as a [remote server](https://osquery.readthedocs.io/en/latest/deployment/remote/#remote-server-api) for Osquery, for configuration, query runs, file carvings, and log collection.

## Zentral configuration

To activate the osquery module, you need to add a `zentral.contrib.osquery` section to the `apps` section in `base.json`.

## HTTP API

There are three HTTP API endpoints available.

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

### /api/osquery/packs/`slug`/

* method: `PUT`, `DELETE`

This endpoint is designed to create or update a standard Osquery pack.

#### Examples

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

```
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @pack.json \
  https://zentral.example.com/api/osquery/packs/first-pack-slug/ \
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


```
$ curl -XDELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/osquery/packs/first-pack-slug/ \
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

```
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

```
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/x-osquery-conf' \
  --data-binary @pack.conf \
  https://zentral.example.com/api/osquery/packs/second-pack-slug/ \
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

```
$ curl -XPUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/yaml' \
  --data-binary @pack.yml \
  https://zentral.example.com/api/osquery/packs/second-pack-slug/ \
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

### `/api/osquery/runs/<int:pk>/results/export/`

* method: POST
* required permissions:
	* `osquery.view_distributedqueryresult`
* optional parameter:
	* `export_format`: One of `csv`, `ndjson` or `json`. Defaults to `csv`.

Use this endpoint to trigger a Osquery run export task. The result of this task will be a file containing all the data collected during the run.

#### Example

```bash
curl -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/osquery/runs/1/results/export/\
  |python3 -m json.tool
```

#### Response

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

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
  https://zentral.example.com/api/osquery/queries/ \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  https://zentral.example.com/api/osquery/queries/?name=GetApps \
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
  https://zentral.example.com/api/osquery/queries/\
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
  https://zentral.example.com/api/osquery/queries/1/ \
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
  https://zentral.example.com/api/osquery/queries/1/\
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
  https://zentral.example.com/api/osquery/queries/1/
```

### /api/osquery/atcs/

#### List all ATCs.

* method: GET
* Content-Type: application/json
* Required permission: `osquery.view_atc`
* Optional filter parameter:
	* `name`: name of the ATC.
    * `configuration`: primary key of the configuration.

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
* Required permission: `osquery.add_atc`

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

#### Get an ATC.

method: GET
Content-Type: application/json
Required permission: `osquery.view_atc`
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

#### Update an ATC.

* method: PUT
* Content-Type: application/json
* Required permission: `osquery.update_atc`
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
  "https://zentral.example.com/api/osquery/atcs/1/" \
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

#### Delete an ATC.

* method: DELETE
* Required permission: `osquery.delete_atc`
* `<int:pk>`: the primary key of the ATC.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/osquery/atcs/1/" 
```

Response (204 No Content)
