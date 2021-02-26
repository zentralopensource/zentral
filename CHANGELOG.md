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
