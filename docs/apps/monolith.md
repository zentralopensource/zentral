# Monolith

Monolith is a Munki server that adds dynamic manifests, catalogs, with progressive patch rollouts to your existing Munki repository.

## Zentral configuration

To activate monolith, you need to add a `zentral.contrib.monolith` section to the `apps` section in `base.json`:

```json
{
  "zentral.contrib.monolith": {}
}
```

You can also configure enrollment packages. In the following example, two enrollment packages are configured: one for the Zentral Munki module, with `munkitools_core` as required PkgInfo, and one for the Zentral Osquery module, with `osquery` as required PkgInfo.

```json
{
  "zentral.contrib.monolith": {
    "enrollment_package_builders": {
      "zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder": {
        "requires": ["munkitools_core"]
      },
      "zentral.contrib.osquery.osx_package.builder.OsqueryZentralEnrollPkgBuilder": {
        "requires": ["osquery"]
      }
    }
  }
}
```

### Repositories

Multiple repositories can be used. There are two kinds of repositories. `S3` and `Virtual`. Use a `S3` repository when you have a Munki repository published in a AWS S3 bucket. Use a `Virtual` repository to upload packages directly in Zentral.

**IMPORTANT** When using AWS S3 buckets, it is recommended to use [AWS instance profiles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html), [task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-iam-roles.html), or any other integrated authentication mechanism to authenticate with the bucket.

### Catalogs

Monolith works better – and is easier to reason about – when all the needed base versions of all pkginfo files are present in at least one catalog, and when more recent pkginfo files are made available in extra catalogs that can be activated for some machines. You could have for example a `production` catalog with the base versions of all the softwares you want to distribute across your fleet, and a `testing` catalog for the more recent versions.

By default, the catalogs from the pkginfo files are **automatically imported and used** in Monolith. If you want to promote a pkginfo file from `testing` to `production`, you would do it in the repository, and trigger a sync (it could be from `bleeding-edge` to `standard`, names are not important as long as they are used consistently).

## Build a manifest

### Create a manifest

In monolith, there is one master manifest per business unit. To create one, to to `Monolith > Manifest` and click on `Create`. Only the existing business units available for API access are listed in the form. If you haven't got one already, go to `Inventory > Business unit` to create one and click on `Enable API enrollment` to prepare it for monolith (or other forms of enrollments in Zentral).

### Add catalogs

Once you have created a manifest, add catalogs to it. You can add tags to a catalog to make it available only to the machines carrying the tags. For example, machines with the `dev` tag can have access to the `development` catalog (linked to the manifest with the `dev`tag), other machines only to the `production` catalog (linked to the manifest without any tags.) This is a great way to test releases progressively.

With the exception of enrollments (mentioned below), for all configuration locations within the Zentral interface where tags are applicable, they're evaluated with "OR" logic. Therefore if a machine has any of the tags attached to a catalog, it will be considered applicable. The lack of tags on a catalog means it would be applied to all machines that either have no tags or are not covered by other tagged catalogs, and you should only have one in that state, set to the lowest priority.

### Add automatic enrollments

Depending on your configuration, you will have the possibility to add enrollment packages. If you have configured monolith following the second configuration example, you can now add one or more osquery enrollment packages, with different tags or configurations. Same as with catalogs above, the lack of tags on an enrollment means it would be applied to all machines that either have no tags or are not covered by other tagged enrollments, and you should only have one in that state.

It's important to note that, unlike how tagging works for catalogs, enrollments employ "AND" logic, meaning all tags added to the enrollment must be present on the machine you'd like them applied to. This is most applicable with Osquery, as it's treated like a package that Monolith adds dynamically to the manifest of 'scoped' machines when it's configured as a 'distributor'. You can use the contained configuration (standalone and separate from the osquery software itself) multiple times with each individual tag you'd like to apply it to, or no tag if you'd like to distribute it to all (untagged) machines.


### Add software via sub-manifests

You can now add software to your manifest. With monolith, we have decided to only allow software to be added in sub-manifests. Go to `Monolith > Sub manifests` to create your first sub-manifest, say `Optional browsers`. Open it and click on `Create new Package` to add a repository package: pick a PkgInfo name and a key (`managed_installs`, `managed_uninstalls`, `default_installs`, `optional_installs`, or `managed_updates`), optionally scoped with a condition, excluded tags and per-tag shards. You can also feature a `default_installs` or an `optional_installs` package in Managed Software Center.

Once you have a sub-manifest, add it to the manifest (from the manifest, click on `Add` in the sub-manifest section). If you pick one or many tags, only the machine carrying any of the tags applied will be offered it.

A package can use more than one key in the same sub-manifest, one time for each key, and each key keeps its own condition, excluded tags and shards. For example, use `optional_installs` and `managed_updates` together. Managed Software Center then offers the package, and Zentral keeps it up to date after a user installs it. Munki updates a `managed_updates` package only if a version of it is already installed.

Do not add the same package with the `managed_installs` and the `managed_uninstalls` keys. Zentral does not prevent it, in one sub-manifest or in two. Munki keeps the install: it does not remove a package that is in the list of managed installs, and it writes a warning.

You also see warnings if you add a package to a sub-manifest before it is in all the applicable catalogs. Use [Conditions](https://github.com/munki/munki/wiki/Conditional-Items) with the munki `catalog` NSPredicate logic to prevent those warnings.

Munki installs a `default_installs` package only if it is an `optional_installs` package too. Zentral adds a `default_installs` package to the two keys. If the sub-manifest has its own `optional_installs` package with the same name and the same condition, Zentral keeps that one, with its own scope.

## PkgInfo sharding

With Zentral Monolith, it is possible to progressively distribute newer versions of packages. It is called *sharding*. Zentral supports an extra key in the PkgInfo `zentral_monolith`. Here is an example:

```xml
<key>zentral_monolith</key>
<dict>
    <key>excluded_tags</key>
    <array>
        <string>Server</string>
    </array>
    <key>shards</key>
    <dict>
        <key>modulo</key>
        <integer>10</integer>
        <key>default</key>
        <integer>0</integer>
        <key>tags</key>
        <dict>
            <key>Canary</key>
            <integer>10</integer>
        </dict>
    </dict>
</dict>
```

First Zentral checks the `excluded_tags`. If a machine has any one of the tags listed in this array, the PkgInfo will not be distributed to the machine. In this example, machines with the *Server* tag will not get this PkgInfo. Then, the `shards` dictionnary is used. `modulo` defines the total number of *shards*. In that example, we have `10` shards (defaults to `100`). The `default` number indicates the default number of shards for which the package is made available. In this example, it is `0` (defaults to `100`), so in that case, by default, no machines will get this PkgInfo. Under the `tags` key, shard values can be specified for different tags. They take precendence over the default value. In this example, machines with the *Canary* tag have a shard value of `10`, meaning that all machines with the *Canary* tag will get this PkgInfo – `10` out of `10` (see `modulo`). To make this PkgInfo available to only 20% of the machine with the *Canary* tag, we would have set the value to `2` – `2` out of `10`. If a machine has multiple tags, and different shard values are defined in the PkgInfo for these tags, it is sufficient that one machine shard value for one of the tags exceeds the threshold defined in the PkgInfo to make the PkgInfo available for this machine.

**IMPORTANT** Make sure that the tags used in the PkgInfo exist in Zentral **before** the repository is synced.

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

### /api/monolith/repositories/

Terraform resource: [`zentral_monolith_repository`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_repository)  
Terraform data source: [`zentral_monolith_repository`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_repository)

A repository is where the Munki packages and pkginfo files come from. See [Repositories](#repositories) for the difference between the backends.

|Attribute|Description|
|---|---|
|`name`|Required, unique.|
|`backend`|`S3`, `AZURE` or `VIRTUAL`. A `VIRTUAL` repository holds packages uploaded directly into Zentral.|
|`s3_kwargs` / `azure_kwargs`|The backend settings. Only the one matching `backend` is used; the other stays `null`.|
|`meta_business_unit`|Optional. Restricts the repository to one business unit. Once set it cannot be changed.|

`provisioning_uid`, `icon_hashes`, `client_resources` and `last_synced_at` are read only. A repository created by provisioning carries a `provisioning_uid`, and can be neither updated nor deleted over the API — it is owned by whatever provisioned it.

#### List all repositories

* method: GET
* PBAC action: `Monolith::Action::"viewRepository"`
* Optional filter parameter:
    * `name`: name of the repository

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/repositories/" \
  |python3 -m json.tool
```

Response

```json
[
    {
        "id": 4,
        "provisioning_uid": null,
        "backend": "VIRTUAL",
        "azure_kwargs": null,
        "s3_kwargs": null,
        "name": "Virtual",
        "meta_business_unit": 7,
        "icon_hashes": {},
        "client_resources": [],
        "created_at": "2026-08-20T13:12:53.147701",
        "updated_at": "2026-08-20T13:12:53.149058",
        "last_synced_at": null
    }
]
```

#### Add a repository

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createRepository"`

Example

repository.json

```json
{
  "name": "S3",
  "backend": "S3",
  "s3_kwargs": {
    "bucket": "acme-munki",
    "region_name": "eu-central-1",
    "prefix": "munki_repo"
  }
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @repository.json \
  "https://$ZTL_FQDN/api/monolith/repositories/" \
  |python3 -m json.tool
```

Response (201 Created)

```json
{
    "id": 5,
    "provisioning_uid": null,
    "backend": "S3",
    "azure_kwargs": null,
    "s3_kwargs": {
        "bucket": "acme-munki",
        "region_name": "eu-central-1",
        "prefix": "munki_repo"
    },
    "name": "S3",
    "meta_business_unit": null,
    "icon_hashes": {},
    "client_resources": [],
    "created_at": "2026-08-20T13:12:53.155983",
    "updated_at": "2026-08-20T13:12:53.156155",
    "last_synced_at": null
}
```

**IMPORTANT** When using AWS S3 buckets, do not put credentials in `s3_kwargs` — use [AWS instance profiles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html), [task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/userguide/task-iam-roles.html) or another integrated authentication mechanism.

### /api/monolith/repositories/`<int:pk>`/

#### Get a repository

* method: GET
* PBAC action: `Monolith::Action::"viewRepository"`
* `<int:pk>`: the primary key of the repository

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/repositories/4/" \
  |python3 -m json.tool
```

#### Update a repository

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateRepository"`
* `<int:pk>`: the primary key of the repository

A provisioned repository cannot be updated. Neither can `meta_business_unit` be changed once it is set.

#### Delete a repository

* method: DELETE
* PBAC action: `Monolith::Action::"deleteRepository"`
* `<int:pk>`: the primary key of the repository

A repository whose catalogs are linked to a manifest cannot be deleted, and neither can a provisioned one.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/repositories/4/"
```

Response (204 No Content)

### /api/monolith/repositories/`<int:pk>`/sync/

#### Fetch the package infos, the icons, the client resources from the repository

During a sync, monolith will import all the available [pkginfo files](https://github.com/munki/munki/wiki/Glossary#info-file-or-pkginfo-file), their [catalogs](https://github.com/munki/munki/wiki/Glossary#catalog), categories, and make them available to the app. It will also import the icon hashes, and get a list of the client resources.

The sync is carried out in the background. A task ID and a URL to poll the task status are returned.

* method: POST
* Content-Type: application/json
* PBAC action:
    * `Monolith::Action::"syncRepository"`

Example:

```
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     https://$ZTL_FQDN/api/monolith/repositories/1/sync/
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```

Poll the `task_result_url` until `unready` is `false`. The result of a successful sync contains the number of objects created or updated per model:

```json
{
  "name": "zentral.contrib.monolith.tasks.sync_repository_task",
  "id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "status": "SUCCESS",
  "unready": false,
  "result": {
    "repository": {"pk": 1, "name": "Main repository"},
    "operations": {
      "catalog": {"created": 1},
      "manifest": {"updated": 2},
      "pkginfo": {"created": 12, "updated": 3},
      "pkginfoname": {"created": 5}
    },
    "status": "SUCCESS"
  }
}
```

Only one sync runs at a time for a given repository. If a sync is already in progress, the task returns immediately with a `SKIPPED` status, and no second sync is carried out:

```json
{
  "repository": {"pk": 1, "name": "Main repository"},
  "status": "SKIPPED"
}
```

### /api/monolith/manifests/

Terraform resource: [`zentral_monolith_manifest`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_manifest)  
Terraform data source: [`zentral_monolith_manifest`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_manifest)

#### List all manifests

* method: GET
* PBAC action: `Monolith::Action::"viewManifest"`
* Optional filter parameters:
    * `name`: name of the manifest
    * `meta_business_unit_id`: ID of the meta business unit

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifests/?name=default" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifests/?meta_business_unit_id=1" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "name": "default",
  "meta_business_unit": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}]
```

#### Add a manifest

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createManifest"`

Examples:

manifest.json

```json
{
  "name": "default",
  "meta_business_unit": 1
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifests/" \
  -d @manifest.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "default",
  "meta_business_unit": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

### /api/monolith/manifests/`<int:pk>`/

#### Get a manifest

* method: GET
* PBAC action: `Monolith::Action::"viewManifest"`
* `<int:pk>`: the primary key of the manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifests/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "default",
  "meta_business_unit": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

#### Update a manifest

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateManifest"`
* `<int:pk>`: the primary key of the manifest

Example:

manifest.json

```json
{
  "name": "default2",
  "meta_business_unit": 2
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifests/1/" \
  -d @manifest.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "name": "default2",
  "meta_business_unit": 2,
  "version": 1,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}
```

#### Delete a manifest

* method: DELETE
* PBAC action: `Monolith::Action::"deleteManifest"`
* `<int:pk>`: the primary key of the manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifests/1/"
```

Response (204 No Content)

### /api/monolith/manifests/`<int:pk>`/cache_servers/

#### Register a Munki cache server

* method: POST
* Content-Type: application/json
* PBAC actions — **all three** are required:
    * `Monolith::Action::"updateManifest"`
    * `Monolith::Action::"createCacheServer"`
    * `Monolith::Action::"updateCacheServer"`
* `<int:pk>`: the primary key of the manifest.

Use this endpoint from a [Munki cache server](https://github.com/munki/munki/wiki/Managed-Software-Center-Preferences) to register itself with a manifest. Zentral then serves that cache server's `base_url` to the machines reaching it from the same public IP address.

|Attribute|Description|
|---|---|
|`name`|Required. The cache server name. Registering again with the same name updates the existing record rather than adding one.|
|`base_url`|Required. The URL the machines should fetch the packages from.|

The caller's public IP address is recorded from the request — it is not part of the payload.

Example

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Berlin office", "base_url": "http://munki-cache.acme.example.com"}' \
  "https://$ZTL_FQDN/api/monolith/manifests/1/cache_servers/" \
  |python3 -m json.tool
```

Response

```json
{
  "status": 0
}
```

### /api/monolith/catalogs/

Terraform resource: [`zentral_monolith_catalog`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_catalog)  
Terraform data source: [`zentral_monolith_catalog`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_catalog)

#### List all catalogs

* method: GET
* PBAC action: `Monolith::Action::"viewCatalog"`
* Optional filter parameter:
    * `name`: name of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/catalogs/?name=production" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "repository": 1,
  "name": "production",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}]
```

#### Add a catalog

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createCatalog"`
* `repository` is required; **via the API it must reference a Virtual repository** (S3/Azure catalogs are created by syncing the external repo, not through this endpoint). `archived_at` is read-only.

Examples:

catalog.json

```json
{
  "repository": 1,
  "name": "staging"
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/catalogs/" \
  -d @catalog.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 2,
  "repository": 1,
  "name": "staging",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}
```

### /api/monolith/catalogs/`<int:pk>`/

#### Get a catalog

* method: GET
* PBAC action: `Monolith::Action::"viewCatalog"`
* `<int:pk>`: the primary key of the catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/catalogs/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "repository": 1,
  "name": "production",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}
```

#### Update a catalog

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateCatalog"`
* `<int:pk>`: the primary key of the catalog

Example:

catalog.json

```json
{
  "repository": 1,
  "name": "production2"
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/catalogs/1/" \
  -d @catalog.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "repository": 1,
  "name": "production2",
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004",
  "archived_at": null
}
```

#### Delete a catalog

* method: DELETE
* PBAC action: `Monolith::Action::"deleteCatalog"`
* `<int:pk>`: the primary key of the catalog.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/catalogs/1/"
```

Response (204 No Content)

### /api/monolith/conditions/

Terraform resource: [`zentral_monolith_condition`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_condition)  
Terraform data source: [`zentral_monolith_condition`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_condition)

#### List all conditions

* method: GET
* PBAC action: `Monolith::Action::"viewCondition"`
* Optional filter parameter:
    * `name`: name of the condition

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/conditions/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/conditions/?name=desktop" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "name": "laptop",
  "predicate": "machine_type == \"laptop\"",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
}]
```

#### Add a condition

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createCondition"`

Examples:

condition.json

```json
{
  "name": "laptop",
  "predicate": "machine_type == \"laptop\""
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/conditions/" \
  -d @condition.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "laptop",
  "predicate": "machine_type == \"laptop\"",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

### /api/monolith/conditions/`<int:pk>`/

#### Get a condition

* method: GET
* PBAC action: `Monolith::Action::"viewCondition"`
* `<int:pk>`: the primary key of the condition

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/conditions/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "laptop",
  "predicate": "machine_type == \"laptop\"",
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

#### Update a condition

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateCondition"`
* `<int:pk>`: the primary key of the condition

Example:

condition.json

```json
{
  "name": "laptop",
  "predicate": "machine_type == \"laptop\""
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/conditions/1/" \
  -d @condition.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "name": "laptop",
  "predicate": "machine_type == \"laptop\"",
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}
```

#### Delete a condition

* method: DELETE
* PBAC action: `Monolith::Action::"deleteCondition"`
* `<int:pk>`: the primary key of the condition.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/conditions/1/"
```

Response (204 No Content)

### /api/monolith/enrollments/

Terraform resource: [`zentral_monolith_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_enrollment)  
Terraform data source: [`zentral_monolith_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_enrollment)

#### List all enrollments

* method: GET
* PBAC action: `Monolith::Action::"viewEnrollment"`
* Optional filter parameter:
    * `manifest_id`: primary key of the manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/?manifest_id=2" \
  |python3 -m json.tool
```

Response:

```json
[
  {
    "id": 1,
    "manifest": 2,
    "enrolled_machines_count": 0,
    "secret": {
      "secret": "AzZhxoWDXDqpUr06O8SQG53eE7fkiOy0U02uOghjQG3zowXMlJqpblSFXvkk05ak",
      "request_count": 0,
      "id": 3,
      "serial_numbers": [],
      "meta_business_unit": 1,
      "quota": null,
      "tags": [],
      "udids": []
    },
    "version": 1,
    "configuration_profile_download_url": "https://zentral.example.com/api/monolith/enrollments/1/configuration_profile/",
    "plist_download_url": "https://zentral.example.com/api/monolith/enrollments/1/plist/",
    "created_at": "2023-01-10T11:02:51.831544",
    "updated_at": "2023-01-10T11:02:51.831553"
  }
]
```

#### Add an enrollment

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createEnrollment"`

Examples:

enrollment.json

```json
{
  "manifest": 2,
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
  "https://$ZTL_FQDN/api/monolith/enrollments/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 2,
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
  "configuration_profile_download_url": "https://zentral.example.com/api/monolith/enrollments/1/configuration_profile/",
  "plist_download_url": "https://zentral.example.com/api/monolith/enrollments/1/plist/",
  "created_at": "2023-01-10T11:02:51.831544",
  "updated_at": "2023-01-10T11:02:51.831553"
}
```

### /api/monolith/enrollments/`<int:pk>`/

#### Get an enrollment

* method: GET
* PBAC action: `Monolith::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 2,
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
  "configuration_profile_download_url": "https://zentral.example.com/api/monolith/enrollments/1/configuration_profile/",
  "plist_download_url": "https://zentral.example.com/api/monolith/enrollments/1/plist/",
  "created_at": "2023-01-10T11:02:51.831544",
  "updated_at": "2023-01-10T11:02:51.831553"
}
```

#### Update an enrollment

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

enrollment.json

```json
{
  "manifest": 2,
  "secret": {
    "meta_business_unit": 1,
    "serial_numbers": ["0123456789"],
    "tags": []
  }
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/enrollments/1/" \
  -d @enrollment.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "manifest": 2,
  "enrolled_machines_count": 0,
  "secret": {
    "secret": "AzZhxoWDXDqpUr06O8SQG53eE7fkiOy0U02uOghjQG3zowXMlJqpblSFXvkk05ak",
    "request_count": 0,
    "id": 3,
    "serial_numbers": ["0123456789"],
    "meta_business_unit": 1,
    "quota": null,
    "tags": [],
    "udids": []
  },
  "version": 1,
  "configuration_profile_download_url": "https://zentral.example.com/api/monolith/enrollments/1/configuration_profile/",
  "plist_download_url": "https://zentral.example.com/api/monolith/enrollments/1/plist/",
  "created_at": "2023-01-10T11:02:51.831544",
  "updated_at": "2023-01-10T11:02:51.831553"
}
```

#### Delete an enrollment

* method: DELETE
* PBAC action: `Monolith::Action::"deleteEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/1/"
```

Response (204 No Content)

### /api/monolith/enrollments/`<int:pk>`/plist/

The [`zentral_monolith_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_enrollment) Terraform resource exposes this URL as its read-only `plist_url` attribute.

#### Download the enrollment plist file

* method: GET
* PBAC action: `Monolith::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

A plist with the Munki configuration keys, for a custom settings payload on the `ManagedInstalls` preference domain. This is the URL returned as the enrollment's `plist_download_url`.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/1/plist/" \
  --output zentral_monolith_configuration.plist
```

### /api/monolith/enrollments/`<int:pk>`/configuration_profile/

The [`zentral_monolith_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_enrollment) Terraform resource exposes this URL as its read-only `configuration_profile_url` attribute.

#### Download the enrollment configuration profile

* method: GET
* PBAC action: `Monolith::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment.

The same keys as a signed configuration profile, ready to distribute over MDM. This is the URL returned as the enrollment's `configuration_profile_download_url`.

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/enrollments/1/configuration_profile/" \
  --output zentral_monolith_configuration.mobileconfig
```

### /api/monolith/manifest_enrollment_packages/

Terraform resource: [`zentral_monolith_manifest_enrollment_package`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_manifest_enrollment_package)

A manifest enrollment package attaches another module's enrollment — munki, osquery, … — to a manifest, so that monolith adds the corresponding package to the manifest of the machines in scope. The builders available are the ones listed under `enrollment_package_builders` in the [monolith configuration](#zentral-configuration).

|Attribute|Description|
|---|---|
|`manifest`|Required. The primary key of the manifest.|
|`builder`|Required. The dotted path of the builder, exactly as configured in `enrollment_package_builders`.|
|`enrollment_pk`|Required. The primary key of the enrollment to distribute, in the module the builder belongs to.|
|`tags`|The tags a machine must carry to get the package. **All** of them are required — unlike catalogs, enrollment packages use AND logic. Empty means every machine.|

`version` is read only, and bumped whenever the package is rebuilt.

#### List all manifest enrollment packages

* method: GET
* PBAC action: `Monolith::Action::"viewManifestEnrollmentPackage"`
* Optional filter parameters:
    * `manifest_id`: the primary key of a manifest
    * `builder`: the dotted path of a builder

Example

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_enrollment_packages/?manifest_id=1" \
  |python3 -m json.tool
```

Response

```json
[
    {
        "id": 1,
        "manifest": 1,
        "tags": [
            3
        ],
        "builder": "zentral.contrib.osquery.osx_package.builder.OsqueryZentralEnrollPkgBuilder",
        "enrollment_pk": 2,
        "version": 1,
        "created_at": "2026-08-20T13:12:53.147701",
        "updated_at": "2026-08-20T13:12:53.149058"
    }
]
```

#### Add a manifest enrollment package

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createManifestEnrollmentPackage"`

Adding one bumps the manifest version and builds the package. The enrollment it points at becomes owned by monolith — from then on it cannot be updated or deleted through its own module's API.

Example

manifest_enrollment_package.json

```json
{
  "manifest": 1,
  "builder": "zentral.contrib.osquery.osx_package.builder.OsqueryZentralEnrollPkgBuilder",
  "enrollment_pk": 2,
  "tags": [3]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @manifest_enrollment_package.json \
  "https://$ZTL_FQDN/api/monolith/manifest_enrollment_packages/" \
  |python3 -m json.tool
```

### /api/monolith/manifest_enrollment_packages/`<int:pk>`/

#### Get a manifest enrollment package

* method: GET
* PBAC action: `Monolith::Action::"viewManifestEnrollmentPackage"`
* `<int:pk>`: the primary key of the manifest enrollment package.

#### Update a manifest enrollment package

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateManifestEnrollmentPackage"`
* `<int:pk>`: the primary key of the manifest enrollment package.

#### Delete a manifest enrollment package

* method: DELETE
* PBAC action: `Monolith::Action::"deleteManifestEnrollmentPackage"`
* `<int:pk>`: the primary key of the manifest enrollment package.

Deleting one bumps the manifest version and removes the package from the manifests. The underlying enrollment is **kept** — it is released back to its own module, not deleted.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_enrollment_packages/1/"
```

Response (204 No Content)

### /api/monolith/manifest_catalogs/

Terraform resource: [`zentral_monolith_manifest_catalog`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_manifest_catalog)

#### List all manifest catalogs

* method: GET
* PBAC action: `Monolith::Action::"viewManifestCatalog"`
* Optional filter parameters:
    * `manifest_id` ID of the manifest
    * `catalog_id` ID of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/?manifest_id=1" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/?catalog_id=2" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "manifest": 1,
  "catalog": 2,
  "tags": []
}]
```

#### Add a manifest catalog

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createManifestCatalog"`

Examples:

manifest\_catalog.json

```json
{
  "manifest": 1,
  "catalog": 2,
  "tags": [17]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/" \
  -d @manifest_catalog.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 1,
  "catalog": 2,
  "tags": [17]
}
```

### /api/monolith/manifest_catalogs/`<int:pk>`/

#### Get a manifest catalog

* method: GET
* PBAC action: `Monolith::Action::"viewManifestCatalog"`
* `<int:pk>`: the primary key of the manifest catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 1,
  "catalog": 2,
  "tags": [17]
}
```

#### Update a manifest catalog

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateManifestCatalog"`
* `<int:pk>`: the primary key of the manifest catalog

Example:

manifest\_catalog.json

```json
{
  "manifest": 2,
  "catalog": 3,
  "tags": []
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/1/" \
  -d @manifest_catalog.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "manifest": 2,
  "catalog": 3,
  "tags": []
}
```

#### Delete a manifest catalog

* method: DELETE
* PBAC action: `Monolith::Action::"deleteManifestCatalog"`
* `<int:pk>`: the primary key of the manifest catalog.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_catalogs/1/"
```

Response (204 No Content)

### /api/monolith/manifest_sub_manifests/

Terraform resource: [`zentral_monolith_manifest_sub_manifest`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_manifest_sub_manifest)

#### List all manifest sub manifests

* method: GET
* PBAC action: `Monolith::Action::"viewManifestSubManifest"`
* Optional filter parameters:
    * `manifest_id` ID of the manifest
    * `sub_manifest_id` ID of the sub manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/?manifest_id=1" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/?sub_manifest_id=2" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "manifest": 1,
  "sub_manifest": 2,
  "tags": []
}]
```

#### Add a manifest sub manifest

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createManifestSubManifest"`

Examples:

manifest\_sub_manifest.json

```json
{
  "manifest": 1,
  "sub_manifest": 2,
  "tags": [17]
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/" \
  -d @manifest_sub_manifest.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 1,
  "sub_manifest": 2,
  "tags": [17]
}
```

### /api/monolith/manifest_sub_manifests/`<int:pk>`/

#### Get a manifest sub manifest

* method: GET
* PBAC action: `Monolith::Action::"viewManifestSubManifest"`
* `<int:pk>`: the primary key of the manifest sub manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "manifest": 1,
  "sub_manifest": 2,
  "tags": [17]
}
```

#### Update a manifest sub manifest

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateManifestSubManifest"`
* `<int:pk>`: the primary key of the manifest sub manifest

Example:

manifest\_sub_manifest.json

```json
{
  "manifest": 2,
  "sub_manifest": 3,
  "tags": []
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/1/" \
  -d @manifest_sub_manifest.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "manifest": 2,
  "sub_manifest": 3,
  "tags": []
}
```

#### Delete a manifest sub manifest

* method: DELETE
* PBAC action: `Monolith::Action::"deleteManifestSubManifest"`
* `<int:pk>`: the primary key of the manifest sub manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/manifest_sub_manifests/1/"
```

Response (204 No Content)

### /api/monolith/sub_manifests/

Terraform resource: [`zentral_monolith_sub_manifest`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_sub_manifest)  
Terraform data source: [`zentral_monolith_sub_manifest`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/data-sources/monolith_sub_manifest)

#### List all sub manifests

* method: GET
* PBAC action: `Monolith::Action::"viewSubManifest"`
* Optional filter parameter:
    * `name` mame of the manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/?name=Browsers" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "name": "Browsers",
  "description": "The supported browsers",
  "meta_business_unit": null,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}]
```

#### Add a sub manifest

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createSubManifest"`

Examples:

sub\_manifest.json

```json
{
  "name": "Browsers",
  "meta_business_unit": 2
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/" \
  -d @sub_manifest.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "Browsers",
  "description": "",
  "meta_business_unit": 2,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}
```

### /api/monolith/sub_manifests/`<int:pk>`/

#### Get a sub manifest

* method: GET
* PBAC action: `Monolith::Action::"viewSubManifest"`
* `<int:pk>`: the primary key of the sub manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "Browsers",
  "description": "The supported browsers",
  "meta_business_unit": null,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}
```

#### Update a sub manifest

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateSubManifest"`
* `<int:pk>`: the primary key of the sub manifest

Example:

sub\_manifest.json

```json
{
  "name": "Browsers & other tools",
  "description": "The supported browsers and other tools",
  "meta_business_unit": 3
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/1/" \
  -d @sub_manifest.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "name": "Browsers & other tools",
  "description": "The supported browsers and other tools",
  "meta_business_unit": 3,
  "created_at": "2023-01-30T09:59:35.965003",
  "updated_at": "2023-01-30T09:59:35.965004"
}
```

#### Delete a sub manifest

* method: DELETE
* PBAC action: `Monolith::Action::"deleteSubManifest"`
* `<int:pk>`: the primary key of the sub manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifests/1/"
```

Response (204 No Content)

### /api/monolith/sub_manifest_pkg_infos/

Terraform resource: [`zentral_monolith_sub_manifest_pkg_info`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/monolith_sub_manifest_pkg_info)

#### List all sub manifest pkg infos

* method: GET
* PBAC action: `Monolith::Action::"viewSubManifestPkgInfo"`
* Optional filter parameter:
    * `sub_manifest_id` primary key of the mame of the sub manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/?sub_manifest_id=1" \
  |python3 -m json.tool
```

Response:

```json
[{
    "id": 1,
    "sub_manifest": 1,
    "key": "managed_installs",
    "featured_item": false,
    "condition": null,
    "pkg_info_name": "Nudge",
    "shard_modulo": 100,
    "default_shard": 0,
    "excluded_tags": [],
    "tag_shards": [
        {
            "tag": 2,
            "shard": 10
        },
        {
            "tag": 1,
            "shard": 20
        }
    ],
    "created_at": "2023-03-06T09:19:21.342194",
    "updated_at": "2023-03-06T09:19:21.342209"
}]
```

#### Add a sub manifest pkg info

* method: POST
* Content-Type: application/json
* PBAC action: `Monolith::Action::"createSubManifestPkgInfo"`

Examples:

sub\_manifest_pkg_info.json

```json
{
  "sub_manifest": 1,
  "pkg_info_name": "Firefox",
  "featured_item": true,
  "key": "optional_installs",
  "excluded_tags": [2],
  "tag_shards": []
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/" \
  -d @sub_manifest_pkg_info.json \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "sub_manifest": 1,
    "key": "optional_installs",
    "featured_item": true,
    "condition": null,
    "pkg_info_name": "Firefox",
    "shard_modulo": 100,
    "default_shard": 100,
    "excluded_tags": [
        2
    ],
    "tag_shards": [],
    "created_at": "2023-03-06T10:12:09.479512",
    "updated_at": "2023-03-06T10:12:09.479528"
}
```

### /api/monolith/sub_manifest_pkg_infos/`<int:pk>`/

#### Get a sub manifest pkg info

* method: GET
* PBAC action: `Monolith::Action::"viewSubManifestPkgInfo"`
* `<int:pk>`: the primary key of the sub manifest pkg info

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/2/" \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 2,
    "sub_manifest": 1,
    "key": "optional_installs",
    "featured_item": true,
    "condition": null,
    "pkg_info_name": "Firefox",
    "shard_modulo": 100,
    "default_shard": 100,
    "excluded_tags": [
        2
    ],
    "tag_shards": [],
    "created_at": "2023-03-06T10:12:09.479512",
    "updated_at": "2023-03-06T10:12:09.479528"
}
```

#### Update a sub manifest pkg info

* method: PUT
* Content-Type: application/json
* PBAC action: `Monolith::Action::"updateSubManifestPkgInfo"`
* `<int:pk>`: the primary key of the sub manifest pkg info

Example:

sub\_manifest.json

```json
{
  "sub_manifest": 1,
  "pkg_info_name": "Firefox",
  "featured_item": false,
  "key": "optional_installs",
  "excluded_tags": [],
  "tag_shards": [
    {
      "tag": 2,
      "shard": 50
    }
  ]
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/2/" \
  -d @sub_manifest_pkg_info.json \
  |python3 -m json.tool
```

Response:

```
{
    "id": 2,
    "sub_manifest": 1,
    "key": "optional_installs",
    "featured_item": false,
    "condition": null,
    "pkg_info_name": "Firefox",
    "shard_modulo": 100,
    "default_shard": 100,
    "excluded_tags": [],
    "tag_shards": [
        {
            "tag": 2,
            "shard": 50
        }
    ],
    "created_at": "2023-03-06T10:12:09.479512",
    "updated_at": "2023-03-06T10:21:28.001665"
}
```

#### Delete a sub manifest pkg info

* method: DELETE
* PBAC action: `Monolith::Action::"deleteSubManifestPkgInfo"`
* `<int:pk>`: the primary key of the sub manifest pkg info.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/monolith/sub_manifest_pkg_infos/2/"
```

Response (204 No Content)
