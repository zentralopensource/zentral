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
