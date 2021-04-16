# Monolith

Monolith is a Munki server. You need to have a Munki repository. With Monolith you will be able to assemble manifests, enroll your client, monitor all requests, and configure osquery and santa.

## Configuration

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

## Repository sync

### Webhook

Once the monolith app is configured and Zentral reloaded, go to Zentral. There is a new `Monolith` menu, with a `Webhook` sub-menu. Click on it. You will see a `curl` command line that you can use to trigger a repository sync. During a sync, monolith will import all the available [pkginfo files](https://github.com/munki/munki/wiki/Glossary#info-file-or-pkginfo-file), their [catalogs](https://github.com/munki/munki/wiki/Glossary#catalog), categories, and make them available to the app.

### Catalogs

Monolith works better – and is easier to reason about – when all the needed base versions of all pkginfo files are present in at least one catalog, and when more recent pkginfo files are made available in extra catalogs that can be activated for some machines. You could have for example a `production` catalog with the base versions of all the softwares you want to distribute accross your fleet, and a `testing` catalog for the more recent versions.

Monolith can run in one of two modes. By default, the catalogs from the pkginfo files are **automatically imported and used** in Monolith. If you want to promote a pkginfo file from `testing` to `production`, you would do it in the repository, and trigger a sync (it could be from `bleeding-edge` to `standard`, names are not important as long as they are used consistently). This mode would be the one to pick if you already have a pkginfo file auto-promotion setup.

Monolith can also run in **manual mode**. To use this mode, set the `manual_catalog_management` to `true` in the `munki_repository` repository configuration of the `zentral.contrib.monolith` app configuration. In this mode, you can also choose the default name of the catalog that the new pkginfo files will be attached to in Zentral, by setting the `default_catalog` key (default to `Not assigned`). To promote a pkginfo file from one catalog to the other one, you would then have to do it in Zentral.

In either mode, you need to set the catalogs priorities in Zentral. Munki cannot understand that `bleeding-edge` has more recent versions than `standard` (or `testing` > `production`). That's why you need to give the catalogs where the most recent versions of the pkginfo files are, higher priorities (bigger numbers). This way we can make sure that if for example there is firefox 123 in `bleeding-edge`, and 122 in `production`, and that munki gets those two catalogs, that firefox 123 will be installed.

## Build a manifest

### Create a manifest

In monolith, there is one master manifest per business unit. To create one, to to `Monolith > Manifest` and click on `Create`. Only the existing business units available for API access are listed in the form. If you haven't got one already, go to `Inventory > Business unit` to create one and click on `Enable API enrollment` to prepare it for monolith (or other forms of enrollments in Zentral).

### Add catalogs

Once you have created a manifest, add catalogs to it. You can add tags to a catalog to make it available only to the machines carrying the tags. For example, machines with the `dev` tag can have access to the `development` catalog (linked to the manifest with the `dev`tag), other machines only to the `production` catalog (linked to the manifest without any tags.) This is a great way to test releases progressively.

With the exception of enrollments (mentioned below), for all configuration locations within the Zentral interface where tags are applicable, they're evaluated with "OR" logic. Therefore if a machine has any of the tags attached to a catalog, it will be considered applicable.

Using a numeric "priority" designation for catalogs helps you assign a 'weighting' where higher numbers 'win'. Consider this scenario; if you have catalogs named 'dev' 'test' and 'prod' to indicate successively wider testing tracks, they could be assigned priority 3, 2, and 1 accordingly. Attaching tags named 'development' and 'testing' to the respective catalogs (one tag for one catalog) will cause machines with both the 'development' and 'testing' tags to claim the 'dev' catalog, one with just 'testing' would claim 'test', and those with no tags would get 'prod'. 

### Add automatic enrollments

Depending on your configuration, you will have the possibility to add enrollment packages. If you have configured monolith following the second configuration example, you can now add one or more santa enrollment packages, with different tags or configurations. One could have a santa in [MONITOR](https://github.com/google/santa/wiki/Configuration#clientmode) mode, as the default, for the whole fleet, and in [LOCKDOWN](https://github.com/google/santa/wiki/Configuration#clientmode) mode on a subset of machines carrying a certain tag (or exact tag combinations).

It's important to note that, in comparison to how tagging works as described in the previous catalogs section, enrollments employ "AND" logic, meaning all tags added to the enrollment must be present on the machine you'd like them applied to. This is most applicable with Osquery, as it's treated like a package by Monolith adds dynamically to the manifest of 'scoped' machines when monolith is configured as a 'distributor'. You can use the contained configuration (standalone and separate from the osquery software itself) multiple times with each individual tag you'd like to apply it to, or no tag if you'd like to distribute it to all (untagged) machines. (Santa's configuration can alternately be entirely delievred via a configuration profile you'd distribute with MDM, just as you can distribute Osquery and its configuration through any standalone method you prefer, but these notes are applicable if you're using Zentrals available 'apps' in concert.)


### Add software

You can now add software to your manifest. With monolith, we have decided to only allow software to be added in sub-manifests. Go to `Monolith > Sub-Manifest` to create your first manifest, say `Optional browsers`. Click on `Add > Repository package` to add repository packages to it. If you click on `Add > Configuration profile or package` you will be able to upload directly a configuration profile or package to zentral and zentral will distribute it without touching your repository. You can also directly enter a script    with `Add > Script`. Scripts will be [executed by munki](https://github.com/munki/munki/wiki/Managing-Printers-With-Munki#nopkg-method) directly.

Once you have a sub-manifest, add it to the manifest (from the manifest, click on `Add` in the sub-manifest section. If you pick some tags, only the machine carrying the tags will get it.
