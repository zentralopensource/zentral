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

### /api/monolith/repositories/`<int:pk>`/sync/

#### Fetch the package infos, the icons, the client resources from the repository

During a sync, monolith will import all the available [pkginfo files](https://github.com/munki/munki/wiki/Glossary#info-file-or-pkginfo-file), their [catalogs](https://github.com/munki/munki/wiki/Glossary#catalog), categories, and make them available to the app. It will also import the icon hashes, and get a list of the client resources.

* method: POST
* Content-Type: application/json
* Required permission:
    * `monolith.sync_repository`

Example:

```
curl -X POST \
     -H "Authorization: Token $TOKEN" \
     https://$FQDN/api/monolith/repositories/1/sync/
```

Response:

```json
{"status": 0}
```

### /api/monolith/manifests/

#### List all manifests

* method: GET
* Required permission: `monolith.view_manifest`
* Optional filter parameters:
    * `name`: name of the manifest
    * `meta_business_unit_id`: ID of the meta business unit

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifests/?name=default" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifests/?meta_business_unit_id=1" \
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
* Required permission: `monolith.add_manifest`

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
  "https://zentral.example.com/api/monolith/manifests/" \
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
* Required permission: `monolith.view_manifest`
* `<int:pk>`: the primary key of the manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifests/1/" \
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
* Required permission: `monolith.change_manifest`
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
  "https://zentral.example.com/api/monolith/manifests/1/" \
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
* Required permission: `monolith.view_catalog`
* Optional filter parameter:
    * `name`: name of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
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
* Required permission: `monolith.view_catalog`
* `<int:pk>`: the primary key of the catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
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
  "priority": 2
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

### /api/monolith/conditions/

#### List all conditions

* method: GET
* Required permission: `monolith.view_condition`
* Optional filter parameter:
    * `name`: name of the condition

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/conditions/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/conditions/?name=desktop" \
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
* Required permission: `monolith.add_condition`

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
  "https://zentral.example.com/api/monolith/conditions/" \
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
* Required permission: `monolith.view_condition`
* `<int:pk>`: the primary key of the condition

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/conditions/1/" \
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
* Required permission: `monolith.change_condition`
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
  "https://zentral.example.com/api/monolith/conditions/1/" \
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
* Required permission: `monolith.delete_condition`
* `<int:pk>`: the primary key of the condition.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/conditions/1/"
```

Response (204 No Content)

### /api/monolith/enrollments/

#### List all enrollments

* method: GET
* Required permission: `monolith.view_enrollment`
* Optional filter parameter:
    * `manifest_id`: primary key of the manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/enrollments/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/enrollments/?manifest_id=2" \
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
* Required permission: `monolith.add_enrollment`

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
  "https://zentral.example.com/api/monolith/enrollments/" \
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
* Required permission: `monolith.view_enrollment`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/enrollments/1/" \
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
* Required permission: `monolith.change_enrollment`
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
  "https://zentral.example.com/api/monolith/enrollments/1/" \
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
* Required permission: `monolith.delete_enrollment`
* `<int:pk>`: the primary key of the enrollment.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/enrollments/1/"
```

Response (204 No Content)

### /api/monolith/manifest_catalogs/

#### List all manifest catalogs

* method: GET
* Required permission: `monolith.view_manifestcatalog`
* Optional filter parameters:
    * `manifest_id` ID of the manifest
    * `catalog_id` ID of the catalog

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_catalogs/?manifest_id=1" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
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
* Required permission: `monolith.view_manifestcatalog`
* `<int:pk>`: the primary key of the manifest catalog

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
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
{
  "id": 1,
  "manifest": 2,
  "catalog": 3,
  "tags": []
}
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

### /api/monolith/manifest_sub_manifests/

#### List all manifest sub manifests

* method: GET
* Required permission: `monolith.view_manifestsubmanifest`
* Optional filter parameters:
    * `manifest_id` ID of the manifest
    * `sub_manifest_id` ID of the sub manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/?manifest_id=1" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/?sub_manifest_id=2" \
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
* Required permission: `monolith.add_manifestsubmanifest`

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
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/" \
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
* Required permission: `monolith.view_manifestsubmanifest`
* `<int:pk>`: the primary key of the manifest sub manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/1/" \
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
* Required permission: `monolith.change_manifestsubmanifest`
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
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/1/" \
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
* Required permission: `monolith.delete_manifestsubmanifest`
* `<int:pk>`: the primary key of the manifest sub manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/manifest_sub_manifests/1/"
```

Response (204 No Content)

### /api/monolith/sub_manifests/

#### List all sub manifests

* method: GET
* Required permission: `monolith.view_submanifest`
* Optional filter parameter:
    * `name` mame of the manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifests/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifests/?name=Browsers" \
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
* Required permission: `monolith.add_submanifest`

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
  "https://zentral.example.com/api/monolith/sub_manifests/" \
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
* Required permission: `monolith.view_submanifest`
* `<int:pk>`: the primary key of the sub manifest

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifests/1/" \
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
* Required permission: `monolith.change_submanifest`
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
  "https://zentral.example.com/api/monolith/sub_manifests/1/" \
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
* Required permission: `monolith.delete_submanifest`
* `<int:pk>`: the primary key of the sub manifest.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifests/1/"
```

Response (204 No Content)

### /api/monolith/sub_manifest_pkg_infos/

#### List all sub manifest pkg infos

* method: GET
* Required permission: `monolith.view_submanifestpkginfo`
* Optional filter parameter:
    * `sub_manifest_id` primary key of the mame of the sub manifest

Examples:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/" \
  |python3 -m json.tool
```

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/?sub_manifest_id=1" \
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
* Required permission: `monolith.add_submanifestpkginfo`

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
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/" \
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
* Required permission: `monolith.view_submanifestpkginfo`
* `<int:pk>`: the primary key of the sub manifest pkg info

Example:

```bash
$ curl -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/2/" \
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
* Required permission: `monolith.change_submanifestpkginfo`
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
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/2/" \
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
* Required permission: `monolith.delete_submanifest`
* `<int:pk>`: the primary key of the sub manifest pkg info.

Example

```bash
$ curl -X DELETE \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/monolith/sub_manifest_pkg_infos/2/"
```

Response (204 No Content)
