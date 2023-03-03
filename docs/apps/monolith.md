# Monolith

Monolith is a Munki server. You need to have a Munki repository. With Monolith you will be able to assemble manifests, enroll your client, monitor all requests, and configure osquery and santa.

## Zentral configuration

To activate monolith, you need to add a `zentral.contrib.monolith` section to the `apps` section in `base.json`.

### Local repository with osquery optional enrollment

The Munki repository is on the same server as Zentral. Only osquery is proposed for enrollment. The Munki enrollment is always enabled. `munkitools_core` and `osquery` are present in your repository.

```json
{
"zentral.contrib.monolith": {
  "enrollment_package_builders": {
    "zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder": {
      "requires": ["munkitools_core"],
      "optional": false
    },
    "zentral.contrib.osquery.osx_package.builder.OsqueryZentralEnrollPkgBuilder": {
      "requires": ["osquery"],
      "optional": true
    }
  },
  "munki_repository": {
    "backend": "zentral.contrib.monolith.repository_backends.local",
    "root": "/var/lib/munki/repo"
  }
}
```

### S3 repository with santa optional enrollment

The Munki repository is in a S3 bucket. Only santa is proposed for enrollment. The Munki enrollment is always enabled. `munkitools_core` and `santa` are present in your repository.

```json
{
"zentral.contrib.monolith": {
  "enrollment_package_builders": {
    "zentral.contrib.munki.osx_package.builder.MunkiZentralEnrollPkgBuilder": {
      "requires": ["munkitools_core"],
      "optional": false
    },
    "zentral.contrib.santa.osx_package.builder.SantaZentralEnrollPkgBuilder": {
      "requires": ["santa"],
      "optional": true
    }
  },
  "munki_repository": {
    "backend": "zentral.contrib.monolith.repository_backends.s3",
    "aws_access_key_id": "AAAAAAAAAAAAAAAAAAAA",
    "aws_secret_access_key": "SECRET",
    "bucket": "monolith-acme",
    "signature_version": "s3v4",
    "region_name": "eu-central-1",
    "prefix": "path_to_repo_root_in_bucket"
  }
}
```

### Catalogs

Monolith works better – and is easier to reason about – when all the needed base versions of all pkginfo files are present in at least one catalog, and when more recent pkginfo files are made available in extra catalogs that can be activated for some machines. You could have for example a `production` catalog with the base versions of all the softwares you want to distribute across your fleet, and a `testing` catalog for the more recent versions.

Monolith can run in one of two modes. By default, the catalogs from the pkginfo files are **automatically imported and used** in Monolith. If you want to promote a pkginfo file from `testing` to `production`, you would do it in the repository, and trigger a sync (it could be from `bleeding-edge` to `standard`, names are not important as long as they are used consistently). This mode would be the one to pick if you already have a pkginfo file auto-promotion setup.

Monolith can also run in **manual mode**. To use this mode, set the `manual_catalog_management` to `true` in the `munki_repository` repository configuration of the `zentral.contrib.monolith` app configuration. In this mode, you can also choose the default name of the catalog that the new pkginfo files will be attached to in Zentral, by setting the `default_catalog` key (default to `Not assigned`). To promote a pkginfo file from one catalog to the other one, you would then have to do it in Zentral.

In either mode, you need to set the catalogs priorities in Zentral. Munki cannot understand that `bleeding-edge` has more recent versions than `standard` (or `testing` > `production`). That's why you need to give the catalogs where the most recent versions of the pkginfo files are, higher priorities (bigger numbers). This way we can make sure that if for example there is firefox 123 in `bleeding-edge`, and 122 in `production`, and that munki gets those two catalogs, that firefox 123 will be installed.

## Build a manifest

### Create a manifest

In monolith, there is one master manifest per business unit. To create one, to to `Monolith > Manifest` and click on `Create`. Only the existing business units available for API access are listed in the form. If you haven't got one already, go to `Inventory > Business unit` to create one and click on `Enable API enrollment` to prepare it for monolith (or other forms of enrollments in Zentral).

### Add catalogs

Once you have created a manifest, add catalogs to it. You can add tags to a catalog to make it available only to the machines carrying the tags. For example, machines with the `dev` tag can have access to the `development` catalog (linked to the manifest with the `dev`tag), other machines only to the `production` catalog (linked to the manifest without any tags.) This is a great way to test releases progressively.

With the exception of enrollments (mentioned below), for all configuration locations within the Zentral interface where tags are applicable, they're evaluated with "OR" logic. Therefore if a machine has any of the tags attached to a catalog, it will be considered applicable. The lack of tags on a catalog means it would be applied to all machines that either have no tags or are not covered by other tagged catalogs, and you should only have one in that state, set to the lowest priority.

Using a numeric "priority" designation alongside tagging for catalogs helps you assign a 'weighting' where higher numbers 'win'. Consider this scenario; if you have catalogs named 'dev' 'test' and 'prod' to indicate successively wider testing tracks, they could be assigned priority 3, 2, and 1 accordingly. Attaching tags named 'development' and 'testing' to the respective catalogs (one tag for one catalog) will cause machines with both the 'development' and 'testing' tags to claim the 'dev' catalog, whereas one with just 'testing' would claim 'test', and those with no tags (or tags not applied to the other catalogs) would get 'prod'.

### Add automatic enrollments

Depending on your configuration, you will have the possibility to add enrollment packages. If you have configured monolith following the second configuration example, you can now add one or more santa enrollment packages, with different tags or configurations. One could have a santa in [MONITOR](https://github.com/google/santa/wiki/Configuration#clientmode) mode, as the default, for the whole fleet, and in [LOCKDOWN](https://github.com/google/santa/wiki/Configuration#clientmode) mode on a subset of machines carrying a certain tag (or exact tag combinations). Same as with catalogs above, the lack of tags on an enrollment means it would be applied to all machines that either have no tags or are not covered by other tagged enrollments, and you should only have one in that state.

It's important to note that, unlike how tagging works for catalogs, enrollments employ "AND" logic, meaning all tags added to the enrollment must be present on the machine you'd like them applied to. This is most applicable with Osquery, as it's treated like a package that Monolith adds dynamically to the manifest of 'scoped' machines when it's configured as a 'distributor'. You can use the contained configuration (standalone and separate from the osquery software itself) multiple times with each individual tag you'd like to apply it to, or no tag if you'd like to distribute it to all (untagged) machines. (Santa's configuration can alternately be entirely delivered via a configuration profile you'd distribute with MDM, just as you can distribute Osquery and its configuration through any standalone method you prefer, but these notes are applicable if you're using Zentrals available 'apps' in concert.)


### Add software via sub-manifests

You can now add software to your manifest. With monolith, we have decided to only allow software to be added in sub-manifests. Go to `Monolith > Sub-Manifest` to create your first manifest, say `Optional browsers`. Click on `Add > Repository package` to add repository packages to it. If you click on `Add > Configuration profile or package` you will be able to upload directly a configuration profile or package to zentral and zentral will distribute it without touching your repository. You can also directly enter a script    with `Add > Script`. Scripts will be [executed by munki](https://github.com/munki/munki/wiki/Managing-Printers-With-Munki#nopkg-method) directly.

Once you have a sub-manifest, add it to the manifest (from the manifest, click on `Add` in the sub-manifest section). If you pick one or many tags, only the machine carrying any of the tags applied will be offered it.

Two important notes to remember is that you should not have the same package as a managed_install and managed_uninstall on the same 'product' key, just like you would see warnings if you add a product to a sub-manifest before it's available to all of the applicable catalogs. (You can use [Conditions](https://github.com/munki/munki/wiki/Conditional-Items) with the built-in-to-munki `catalog` NSPredicate logic to 'mute'/avoid those warnings.) Also, you cannot add a product as both a managed_update and optional_install in the same sub-manifest, it is recommended to use an additional, separate sub-manifest if that is required.

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

### /api/monolith/repository/sync/

#### Fetch the package infos from the repository

During a sync, monolith will import all the available [pkginfo files](https://github.com/munki/munki/wiki/Glossary#info-file-or-pkginfo-file), their [catalogs](https://github.com/munki/munki/wiki/Glossary#catalog), categories, and make them available to the app.

* method: POST
* Content-Type: application/json
* Required permissions:
    * `monolith.view_catalog`
    * `monolith.add_catalog`
    * `monolith.change_catalog`,
    * `monolith.view_pkginfoname`
    * `monolith.add_pkginfoname`
    * `monolith.change_pkginfoname`,
    * `monolith.view_pkginfo`
    * `monolith.add_pkginfo`
    * `monolith.change_pkginfo`,
    * `monolith.change_manifest`

Example:

```
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     https://$FQDN/api/monolith/repository/sync/
```

Response:

```json
{"status": 0}
```

### /api/monolith/manifests/

#### List all manifests

* method: GET
* Content-Type: application/json
* Required permission: `monolith.view_manifest`
* Optional filter parameters:
  * `name`: name of the manifest
  * `meta_business_unit_id`: ID of the meta business unit

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/?name=default" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/?meta_business_unit_id=1" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "name": "default",
  "meta_business_unit_id": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}]
```

#### Add a manifest

* method: POST
* Content-Type: application/json
* Required permission: `monolith.add_manifest`

Examples:

manifest.json

```json
{
  "name": "default",
  "meta_business_unit_id": 1
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/" \
  -d @manifest.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "default",
  "meta_business_unit_id": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

### /api/monolith/manifests/`<int:pk>`/

#### Get a manifest

* method: GET
* Content-Type: application/json
* Required permission: `monolith.view_manifest`
* `<int:pk>`: the primary key of the manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "default",
  "meta_business_unit_id": 1,
  "version": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004"
}
```

#### Update a manifest

* method: PUT
* Content-Type: application/json
* Required permission: `monolith.change_manifest`
* `<int:pk>`: the primary key of the manifest

Example:

manifest.json

```json
{
  "name": "default2",
  "meta_business_unit_id: 2
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifests/1/" \
  -d @manifest.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "name": "default2",
  "meta_business_unit_id": 2,
  "version": 1,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004"
}
```

#### Delete a manifest

* method: DELETE
* Required permission: `monolith.delete_manifest`
* `<int:pk>`: the primary key of the manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest/1/"
```

Response (204 No Content)

### /api/monolith/catalogs/

#### List all catalogs

* method: GET
* Content-Type: application/json
* Required permission: `monolith.view_catalog`
* Optional filter parameter:
  * `name`: name of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/catalogs/?name=production" \
  |python3 -m json.tool
```

Response:

```json
[{
  "id": 1,
  "name": "production",
  "priority": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}]
```

#### Add a catalog

* method: POST
* Content-Type: application/json
* Required permission: `monolith.add_catalog`

Examples:

catalog.json

```json
{
  "name": "staging",
  "priority": 10
}
```

```bash
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/catalogs/" \
  -d @catalog.json \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 2,
  "name": "staging",
  "priority": 10,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}
```

### /api/monolith/catalogs/`<int:pk>`/

#### Get a catalog

* method: GET
* Content-Type: application/json
* Required permission: `monolith.view_catalog`
* `<int:pk>`: the primary key of the catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/catalogs/1/" \
  |python3 -m json.tool
```

Response:

```json
{
  "id": 1,
  "name": "production",
  "priority": 1,
  "created_at": "2023-01-30T09:39:35.965003",
  "updated_at": "2023-01-30T09:39:35.965004",
  "archived_at": null
}
```

#### Update a catalog

* method: PUT
* Content-Type: application/json
* Required permission: `monolith.change_catalog`
* `<int:pk>`: the primary key of the catalog

Example:

catalog.json

```json
{
  "name": "production2",
  "meta_business_unit_id: 2
}
```

```bash
$ curl -X PUT \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/catalogs/1/" \
  -d @catalog.json \
  |python3 -m json.tool
```

Response:

```
{
  "id": 1,
  "name": "production2",
  "priority": 2,
  "created_at": "2023-01-30T09:49:35.965003",
  "updated_at": "2023-01-30T09:49:35.965004",
  "archived_at": null
}
```

#### Delete a catalog

* method: DELETE
* Required permission: `monolith.delete_catalog`
* `<int:pk>`: the primary key of the catalog.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/catalogs/1/"
```

Response (204 No Content)

### /api/monolith/manifest_catalogs/

#### List all manifest catalogs

* method: GET
* Content-Type: application/json
* Required permission: `monolith.view_manifestcatalog`
* Optional filter parameter:
  * `manifest_id` ID of the manifest
  * `catalog_id` ID of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/?manifest_id=1" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/?catalog_id=2" \
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
* Required permission: `monolith.add_manifestcatalog`

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
  "https://zentral.example.com/api/monolith/manifest_catalogs/" \
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
* Content-Type: application/json
* Required permission: `monolith.view_manifestcatalog`
* `<int:pk>`: the primary key of the manifest catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/1/" \
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
* Required permission: `monolith.change_manifestcatalog`
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
  "https://zentral.example.com/api/monolith/manifest_catalogs/1/" \
  -d @manifest_catalog.json \
  |python3 -m json.tool
```

Response:

```
  "id": 1,
  "manifest": 2,
  "catalog": 3,
  "tags": []
```

#### Delete a manifest catalog

* method: DELETE
* Required permission: `monolith.delete_manifestcatalog`
* `<int:pk>`: the primary key of the manifest catalog.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/1/"
```

Response (204 No Content)
