# RBAC permissions for API endpoints

Root key: `permissions`

As of Zentral releases which include RBAC support ([~v2021.1](https://github.com/zentralopensource/zentral/releases/tag/v2021.1)), various API endpoints were added which require granularly-applied permissions via API tokens. In this page we will cover where to configure permissions, what permissions to enable across the listed API endpoints, and a supplemental, recommended group-first way to create a token for a service account. In addition to the specific polling process when performing inventory exports, we'll also cover an 'inbound' endpoint for applying tags to machines (which allow for scoping or classifications inherited elsewhere in Zentral).

As a reminder, the 'gitops' workflow for interacting with [Santa rulesets](../../apps/santa/#http-api) and [osquery packs](../../apps/osquery/#http-api) are discussed in each of their HTTP API sections, respectively.

## Access

### Groups

Under the Setup menu with the gear icon, you'd see Users and Groups. Clicking Groups would bring you to the list of any existing groups, with their associated Users and Service accounts. You can either edit the existing ones on the rightmost column, or click on the hyperlink name of one for details, and click the Update button towards the bottom to edit it as needed.

Clicking the Create button with a plus icon at the top of the `accounts/groups` page allows you to enter a name and choose from an extensive list of permissions for either a user or service account. The permissions are listed in three columns: 'app', referring to the general 'contrib' module you would need to have active and loaded in your base.json, then the more-specific moving part of the 'app' you're managing access to, and the 'action(s)' you're specifying.

## Permissions

As it would require some parsing if you were just looking at the raw code, the following table breaks down all API endpoints (including Santa, osquery, and inbound tagging) after the URL of your Zentral instance:

| export, "outbound" api endpoints                                                              | actions |
:---------------------------------------------------------------------------------------------  | :--------------------------- 
| /api/inventory/machines/export                                                                | Can view machine snapshot |
| /api/inventory/macos_apps/export                                                              | Can view osx app | 
|                                                                                               | Can view osx app instance |
| /api/inventory/machines/export_macos_app_instances                                            | Can view osx app |
|                                                                                               | Can view osx app instance |
| /api/inventory/machines/export_program_instances                                              | Can view program instance |
| /api/inventory/machines/export_deb_packages                                                   | Can view deb package |

### Inbound                                                                                   

The `/api/inventory/machines/tags` endpoint enables you to write tag to machines, located via users associated with computers. Principal user detection relies on Munki either discovering a O365, Gsuite account, or if those are not present, the logged in users short username. This is an example payload you would POST:
```
{"tags": {
  "NameOfTheTaxonomy": "NameOfTheTag",
  "TaxonomyToClear": null
  },
  "principal_users": {
     "unique_ids": ['063955281479798017433'],
     "principal_names": ['myrtle', 'mavis@companymanageddoma.in']
  }
}
```
At the dict in the top of this payload you see an example of either setting a single tag per taxonomy, or clearing any tags if you'd like them removed. For the users to be located, you must either populate the array of unique_ids (corresponding to GSuite or O365 account IDs) or principal_names with the complete set you want maintained (or it would remove the tags from the associated machines). You'd get a result like from the osquery pack or santa ruleset endpoints letting you know a overview of what actions were taken, if necessary.

```
{
    "machines": {
        "found": 2
    },
    "tags": {
        "added": 2,
        "removed": 0
    }
}
```


| "inbound", write-access api endpoints | actions |
:- | :-----------
| /api/inventory/machines/tags                       | Can add tag                 |
|                                                    | Can add taxonomy            |
|                                                    | Can add machine tag         |
|                                                    | Can delete machine tag      |
| /api/santa/ingest/fileinfo/                        | Can add file                |
| /api/santa/rulesets/update/                        | Can add ruleset             |
|                                                    | Can change ruleset          |
|                                                    | Can add rule                |
|                                                    | Can change rule             |
|                                                    | Can delete rule             |
| /api/osquery/packs/\<slug>\/                         | Can add pack                |
|                                                    | Can change pack             |
|                                                    | Can add query               |
|                                                    | Can add pack query          |
|                                                    | Can change pack query       |
|                                                    | Can delete pack query       |

## Endpoint Details

The plain "machine/export" endpoint is essentially a hardware dump of all assets across each 'source'(Jamf, Monolith, etc.), which would be fetched as separate .csv's compressed in a single zip.

### Process to call API endpoint

Calling any of these 'export' endpoints should begin with an authenticated POST to initiate the process on your worker instance, after which you'd poll (via GETs) a task ID returned by the initial POST. When the GET returns that the download is ready, you'd perform a subsequent GET for the download URL, and follow redirects as necessary with the same token as auth to fetch the export.

### Software inventory exports

While deb packages and program instances may be obvious from their naming that they relate to the Ubuntu and Windows OS platforms respectively, the concept of an instance vs. the app itself relates to what you see as an end result. Instances is a heavy db dump where each software title is inventoried and output as single lines, correlated to the serial number the app is installed on, per source. With many computers you can expect these files to be very large.
As asset management would also want to know raw total counts of software per version, the separate macos_apps endpoint is provided.

