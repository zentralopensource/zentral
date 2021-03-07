## 2021.2 (Unreleased)

### Features

The Osquery module is being completely overhauled. Better dedicated Osquery models are replacing the legacy Osquery probes.

The stores are being updated (Datadog, Splunk), and the dependency on Elasticsearch for the UI is progressively being removed. Extra fingerprinting is put in place in the event pipeline, to be able to filter the events without relying on the full indexing of the event objects.

### Improvements

Some work is being done to speedup the AWS SNS publisher, and the bulk storage of events is being tested with the compatible stores.

### Backward incompatibilities

#### 🧨 Major Osquery migration

Legacy Osquery probe queries will be migrated, but **make sure you have backups** before upgrading!

You will have to manually review and update the Osquery configurations after the upgrade, to re-enable the scheduled queries.

Older distributed query results will not be deleted from the event stores, but you will not be able to fetch them from the Zentral UI.

Older file carving archives will not be deleted from the Django storage, but you will not be able to fetch them from the Zentral UI.

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
