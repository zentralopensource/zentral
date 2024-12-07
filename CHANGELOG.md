## 2024.1 (TBD)

### Features (some, not all…)

#### MDM

Support for custom DDM declarations.

Support for DDM software updates, with automatic enforcement of the latest OS versions.

Support for enforced software update to the latest OS versions during ADE.

Available software updates from the official Apple JSON feed and the Software Update Product ID.

Filevault configuration during Setup Assistant with automatic PRK escrow, rotation and database encryption.

Automatic recovery lock and firmware password management, with key rotation and database encryption.

Automatic device tagging based on ADE authentication and IdP SCIM group memberships.

VPP apps with automatic app device assignments.

Support for more manual MDM commands and custom MDM commands.

Variable substitution in MDM InstallApplication command config.

Support for the MDM header signature authentication scheme.

#### APIs / Terraform

Much improved API coverage, many more [Terraform provider](https://registry.terraform.io/providers/zentralopensource/zentral/latest) resources.

Better Terraform exports.

#### Identity provider

Add SCIM provisioning.

Add Realm user support for up to two custom attributes.

Add Realm group mapping claim separator.

#### Munki

Add Munki _Script Checks_. Those are Zentral compliance checks based on shell scripts, run by the Munki agent. They contribute to the reported health of the machines in the Zentral inventory, like the Inventory and Osquery based Zentral compliance checks.

Support for multiple Munki repositories, and virtual repositories with direct package upload.

Support for the Munki `default_installs` key.

#### Santa

Support for the [Santa Signing ID rules](https://santa.dev/concepts/rules.html#signing-id-rules).

Support for the [Santa CDHASH rules](https://santa.dev/concepts/rules.html#cdhash-rules).

Support for the `SyncExtraHeaders` configuration key and implementation of the authentication via `Zentral-Authorization` header.

Exception portal.

#### Inventory

Jamf extensions attribute to principal user mapping.

Microsoft Intune inventory sync.

#### Events

New Zentral Audit events to track configuration changes.

New `zentral.core.stores.backends.snowflake` store backend for [Snowflake](https://www.snowflake.com/).

New `zentral.core.stores.backends.panther` store backend for [Panther](https://panther.com/)

#### One more thing…

🚧 Alpha release of the new UI.

### Backward incompatibilities

#### 🧨 Santa bundle rules removed

Zentral doesn't support rules with a Bundle as target anymore. A migration will translated those rules into Binary rules.

#### 🧨 Santa agent authentication

The Santa agent is now authenticated with an extra `Zentral-Authorization` header that must contain the enrollment secret. The older endpoints are still active, but they are deprecated and will be removed in the near future.

#### 🧨 dependency on Redis

Redis is now required. It can be used as cache and background task backend, and replaces Memcached.

#### 🧨 updated monolith configuration

The Monolith repository is not configured in `base.json` anymore. Multiple Monolith repositories can be managed using the API or the GUI.

#### 🧨 updated `/api/inventory/machines/tags/` API endpoint

To add more flexibility, the payload for this API endpoint has changed. Please refer to [the documentation](https://docs.zentral.io/en/latest/apps/inventory/#apiinventorymachinestags).

#### 🧨 new URLs for Monolith

The Monolith URLs used by the Munki agent are now prefixed with `public/` by default. Configuration profiles (use the enrollment bump version button to force new ones) are including those new URLs, but agents currently deployed will keep using the legacy URLs until they are reconfigured. To mount the legacy endpoints required by those agents, set the optional configuration key `mount_legacy_public_endpoints` to `true` in the `zentral.contrib.monolith` app section of the `base.json` configuration in your deployments.

#### 🧨 new URLs for Munki

The Munki URLs used by the Munki agent are now prefixed with `public/` by default. Enrollment packages (use the enrollment bump version button to force new ones) are including those new URLs, but agents currently deployed will keep using the legacy URLs until they are reconfigured. To mount the legacy endpoints required by those agents, set the optional configuration key `mount_legacy_public_endpoints` to `true` in the `zentral.contrib.munki` app section of the `base.json` configuration in your deployments.

#### 🧨 `nagios` and `simplemdm` legacy apps removed

Please contact us if you are using one of those apps!

#### 🧨 new URLs for the Realms authentication

The Realms URLs used for authentication are now prefixed with `public/` by default. To mount the legacy endpoints required by existing SSO configurations, set the option key `mount_legacy_public_endpoints` to `true` in the `realms` app section of the `base.json` configuration in your deployments.

#### 🧨 munki/monolith manifest names are unique now

The monolith manifest names can be used as identifiers now. If you have multiple manifests with the same name in Zentral, the database migration cannot be applied. Please make sure the names are unique before upgrading.

#### 🧨 new URLs for Osquery

The Osquery URLs used by the Osquery agent are now prefixed with `public/` by default. Enrollment packages (use the enrollment bump version button to force new ones) are including those new URLs, but agents currently deployed will keep using the legacy URLs until they are reconfigured. To mount the legacy endpoints required by those agents, set the optional configuration key `mount_legacy_public_endpoints` to `true` in the `zentral.contrib.osquery` app section of the `base.json` configuration in your deployments.

#### 🧨 new URLs for Santa

As Osquery, the Santa URLs used by Santa agent are also affected with `public/` prefix by default for syncing and enrollment configuration. To mount the legacy endpoints required by those agents, set the optional configuration key `mount_legacy_public_endpoints` to `true` in the `zentral.contrib.santa` app section of the `base.json` configuration in your deployments.

#### 🧨 Filebeat module removed

Extra logs can still be shipped to Zentral, but Zentral doesn't need to manage the Filebeat enrollments.

#### 🧨 Santa event serialization

The `signing_chain` of the santa events is now flattened into the `signing_cert_0`, `signing_cert_1`, `signing_cert_2` keys by default. Set the `flatten_events_signing_chain` option in the app settings to `false` to keep using the legacy serialization.

## 2022.2 (August 13, 2022)

**IMPORTANT:** The License has changed! Most of the code stays under the Apache license, but some modules, like the SAML authentication, or the Splunk event store are licensed under a new source available license, and require a subscription when used in production.

### Features (some, not all…)

New `zentral.core.stores.backends.opensearch` store backend to solve the connection issues with OpenSearch instances.

Automatically managed out of sync incidents for the santa enrolled machines.

API tokens are hashed before being stored in the database.

Managed MDM payload renewal.

Flexible MDM payload SCEP configuration.

Extra API endpoints used by the new [terraform provider](https://github.com/zentralopensource/terraform-provider-zentral).

Docker images upgraded to python3.10 bullseye.

Add [sumo logic](https://www.sumologic.com/) event store.

### Backward incompatibilities

#### 🧨 AWS auth for elasticsearch

The AWS authentication for elasticsearch has been removed. It is only available for the `zentral.core.stores.backends.opensearch` store backend.

#### 🧨 elasticsearch-py version 8.3.1

The newer elasticsearch clients will refuse to connect to an OpenSearch instance. Use the new `zentral.core.stores.backends.opensearch` store backend instead.

#### 🧨 Elasticearch 8.3.2

The elasticsearch version in the docker compose configuration has been upgraded to 8.3.2. If you have an existing deployment, you need to first upgrade to the lastest 7.X version (7.15.2 ATM), before upgrading to this version.

#### 🧨 PostgreSQL 14

The PostgreSQL version in the docker compose configuration has been upgraded to 14. If you have an existing deployment, you need to first backup your DB and reimport it after the upgrade.

#### 🧨 Probe feeds are not pulled anymore

The URL field of the probe feeds has been removed. To update a feed, you need
to use the API and push it.

#### 🧨 Santa configuration changes

The Zentral Santa configuration doesn't keep track anymore of the configuration keys that can only be set in a configuration profile. If you rely on Zentral to keep track of your Santa configuration profiles, do not forget to download them before applying the DB migrations.

The support for the Santa agent pre v1.14 has been dropped.

## 2022.1 (May 16, 2022)

### Features (some, not all…)

Add Santa team ID rules.

Multiple Elasticsearch indices/aliases for event lifecycle management.

Add event routing keys. Use routing keys for the event stores.

Refactor Puppet inventory souce.

Add Workspace ONE inventory source.

Add iOS and Android apps to inventory.

Upgrade to Django 3.2 LTS.

Replace U2F by WebAuthN for 2FA.

Add API endpoints for Munki, Osquery, and Santa enrollements.

Add shards in Monolith/Munki PkgInfos and Submanifests.

Add last seen filter to inventory machine list

Add inventory (JMESPath) and Osquery compliance checks

Collect AWS EC2 information in inventory.

Collect macOS profiles & payloads in inventory.

New incident architecture. Add incidents for Munki reinstalls and failed installs.

Bulk store worker on GCP Pub/Sub.

Add Santa metrics and targets views.

Add event linked objects search.

Splunk can be used as frontend store.

Shards for Santa Allow unknown and Upload all events options

Munki managed installs collection and metrics

Monolith managed installs collection and metrics

mdmcerts management commannd for the MDM vendor and push certificates

Secret engines can be used to encrypt the secrets stored in the database.

### Backward incompatibilities

#### 🧨 Python compatibility change

Zentral support for python 3.6 dropped. Zentral supports python 3.7, 3.8, 3.9, and 3.10.

#### 🧨 GCP Pub/Sub subscription filters removed

They could not be updated, and are not compatible with the event routing keys.

#### 💣 Puppet integration

The Puppet module has been refactored, and PuppetDB instances must be configured in the setup section.

#### ⚠️  event filters for event stores

`excluded_event_types` and `included_event_types` are deprecated. They have been replaced by `excluded_event_filters` and `included_event_filters` respectively.

## 2021.2 (October 1, 2021)

### Features

The Osquery module has been completely overhauled. Better dedicated Osquery models replace the legacy Osquery probes.

The MDM module has been completely overhauled. There is a new Blueprint system, with a feedback mechanism to make sure artifacts have been installed on the endpoints. A first implementation of the declarative MDM protocol is also included.

The stores were updated (Datadog, Splunk), and the dependency on Elasticsearch for the UI is progressively being removed. Extra fingerprinting is put in place in the event pipeline, to be able to filter the events without relying on the full indexing of the event objects.

### Improvements

AWS SNS/SQS queues speedup (multithreading, subscription filters, …).

Bulk or concurrent storage of events works with the compatible queues/stores.

### Backward incompatibilities

#### 🧨 Major Osquery migration

Legacy Osquery probe queries will be migrated, but **make sure you have backups** before upgrading!

You will have to manually review and update the Osquery configurations after the upgrade, to re-enable the scheduled queries.

Older distributed query results will not be deleted from the event stores, but you will not be able to fetch them from the Zentral UI.

Older file carving archives will not be deleted from the Django storage, but you will not be able to fetch them from the Zentral UI.

#### 🧨 Major MDM migration

The MDM configuration will have to be manually imported in the new MDM system.

#### Probe events & stores

See [#186](https://github.com/zentralopensource/zentral/pull/186)

The probes matching an event are now serialized in that event. Inactive probes cannot be used anymore to look at past events, because the stored events do not contain a reference to these probes.

## 2021.1 (February 26, 2021)

### Features

The Santa module has been completely overhauled.

 * Implementation of the [Bundle info/events](https://santa.readthedocs.io/en/latest/details/events/#bundle-events) part of the Santa sync
 * ALLOWLIST_COMPILER rules
 * API endpoint to [apply sets of rules](https://zentral.readthedocs.io/en/latest/apps/santa/#apisantarulesetsupdate) to one or many Santa configurations
 * API endpoint to [ingest the `santactl fileinfo` JSON output](https://zentral.readthedocs.io/en/latest/apps/santa/apisantaingestfileinfo) to populate the sha256 and apps in Zentral

### Backward incompatibilities

Rules are **not managed in the Probes anymore**. They are managed under each *Configuration* in the Santa Setup.

If you upgrade from a previous Zentral release, please, make a backup! The existing rules in the Santa probes will be automatically migrated to each existing Zentral Santa *Configuration*. You need to carefully review them afterwards.

You can read more about it in the [updated documentation](https://zentral.readthedocs.io/en/latest/apps/santa/).
