## 2026.6


### Features


#### Inventory

The inventory JMESPath compliance check publishes the same `zentral_audit` events as the other objects now, from the web console and from the API.


#### MDM

A data asset can be created and updated with its content in the request now, base 64 encoded in the new `source` attribute, and not only with a `file_uri` that points to an object in an S3 bucket. `file_uri` and `source` are mutually exclusive, and one of them is required. Zentral computes `file_sha256` from a `source`, and requires it only with a `file_uri`. A `file_sha256` given with a `source` is verified against the content. A data asset created from a `source` has no filename.

The `file_uri` and `file_sha256` attributes of the data asset endpoints are not required fields anymore. A request without `file_uri` and without `source` gives one error for the two of them, and not one "This field is required." for each attribute.

Zentral uses version 10 of the Apple device assignment protocol now, and not version 3. Apple sends more device attributes with it. The web console and the DEP device endpoints show them: the Wi-Fi, Bluetooth and Ethernet MAC addresses, the EID, the IMEI and MEID numbers, the MDM migration deadline, and if the device replaces another one. The list endpoint has a new `is_replacement_device` filter.

Only the devices that a synchronization reports get the new attributes. A delta synchronization reports the devices that changed, so a full synchronization (`?full_sync=true`) is necessary to get the attributes of all the devices. It posts one `dep_device_change` event per device, one time only: the new attributes get their value, and the `os` of an iPad changes from `iOS` to `iPadOS`.

Apple can throttle the assignment of the default enrollment. Zentral counts the throttled devices apart from the failed ones now, and assigns them again after the delay Apple gives.

An operator can force the install of an artifact on an enrolled device or on an enrolled user. Use it when a target artifact is stuck: a certificate distributed via DDM that failed and does not recover, a Store App that never updates, or an installed profile that must be applied again. The *Force install* button is on the artifact rows of the device and user pages, and the new `force_install` API endpoints do the same. The action is gated by the new `MDM::Action::"forceInstallArtifact"` PBAC action, with the artifact type, ID, name and the channel in the context. The stale pending commands linked to the artifact are deleted, and the target is notified.

New paginated API endpoints list the target artifacts of the enrolled devices and of the enrolled users, with device or user, artifact, status and pending forced install filters. Filter on an artifact and a status to find the devices where it is stuck, fleet wide.

The `target_artifact_update` events carry two new attributes: `force_install_requested_at`, set while a forced install is pending, and `retries_exhausted`, `true` on the failure of the final install attempt of an artifact, when no automatic retry will follow. The event of a forced install request carries the full request context of the operator.


#### Monolith

Every key of a sub manifest package has the same scope: a condition, excluded tags and shards. You can remove a package from a part of your fleet first, then increase the shard. Excluded tags that you set for a *Managed Uninstalls* package through the API apply now. The machines that carry those tags keep the package.

A sub manifest package can use more than one key, one time for each key, and each key keeps its own scope. Use `optional_installs` and `managed_updates` together to offer a package in Managed Software Center, and to keep it up to date after a user installs it. Munki updates a `managed_updates` package only if a version of it is already installed.

Zentral adds a `default_installs` package to the `optional_installs` of the sub manifest, because munki installs it only if it is an optional install too. If the sub manifest has its own `optional_installs` package with the same name and the same condition, Zentral keeps that one, with its own scope.

The Monolith API publishes the same `zentral_audit` events as the web console now. The catalogs, the conditions, the enrollments and the manifest enrollment packages changed with no record of it.


#### Munki

The Munki API publishes the same `zentral_audit` events as the web console now, for the enrollments.

The Munki web console publishes a `zentral_audit` event when a user creates an enrollment, deletes an enrollment, or increases the version of an enrollment. These three changes had no record.

The audit events of a Munki enrollment are also on the page of its configuration now, like the Osquery, Santa and Turbo enrollments. The Munki enrollment gave no link to its configuration, so its events were only on the enrollment.


#### Osquery

Zentral publishes a `zentral_audit` event when a user creates, updates or deletes an Osquery object from the web console: automatic table constructions, configurations, configuration packs, enrollments, file categories, packs, pack queries, queries and distributed query runs. Each event carries the full value of the object before and after the change, and the user, the source IP and the request that made it.

A run that stops other runs of the same query — the "Halt current runs" option — now publishes one event for each stopped run. Before, the other runs ended with no record of it.

An import of a standard Osquery pack publishes a `zentral_audit` event for each object it changes, next to the `osquery_pack_update` event that reports the import. The import changed packs, queries and pack queries with no audit trail, and it is the only way to change several of them at once.

The Osquery API publishes the same `zentral_audit` events as the web console now. The nine endpoints of the automatic table constructions, the configurations, the configuration packs, the enrollments, the file categories, the packs and the queries were the last ones that changed an object with no record of it.


#### Santa

The Santa API publishes the same `zentral_audit` events as the web console now, for the enrollments.

The Santa web console publishes a `zentral_audit` event when a user creates an enrollment. This change had no record.

A clean sync — `CLEAN` or `CLEAN_ALL` — can be queued for an enrolled machine from its machine page or from the API, and cancelled before its next preflight. The new `Santa::Action::"forceCleanSync"` PBAC action gives the permission, and accepts a meta business unit and a sync type.

New `/api/santa/enrolled_machines/` endpoint.

The enrolled machine and sync state metrics are bucketed by the age of the last postflight now, like the active machine metric. A machine that stopped reporting kept its Santa version in the totals forever. The `le` label selects the machines that reported in the last 1, 7, 14, 30, 45 or 90 days, and `+Inf` counts all of them.


### Backward incompatibilities


#### 🧨 Osquery pack import events

The `osquery_pack_query_update` events are removed. The import of a standard pack publishes a `zentral_audit` event for each pack query it changes, and one for each pack and each query as well. Read those instead: they carry the whole value of the object before and after the change, where the removed event carried a partial difference, and they reach the page of the object.

The `osquery_pack_update` event does not carry the `updates` attribute anymore, for the same reason: the audit event of the pack carries the two values. The response of `PUT /api/osquery/packs/<slug>/` is unchanged and still carries `updates`.

An `osquery_pack_query_update` event reported a change to a pack query and a change to the query it schedules together, with the SQL of the query under the `query` key. These are two audit events now, one for each object.


#### 🧨 Osquery API list endpoints

The list endpoints of the Osquery API answer with a page and not with an array. Read the objects in the `results` attribute, and follow `next` to read the pages that come after the first one. The `limit` and the `offset` query parameters select a page. The default limit is 50, and the maximum limit is 500.


#### 🧨 PATCH on the Osquery API

`PATCH` gives a `405 Method Not Allowed` on the Osquery API. Use `PUT`, and send all the attributes of the object. A `PATCH` did not do a correct partial update: it gave a 500 on the queries and on the enrollments, and it renamed a file category or a pack, because the slug was computed from a name that the request did not contain.


#### 🧨 Osquery query payload in events

The `version` attribute of an Osquery query in an event payload is the version of the query again. It was the minimum Osquery version of the query, which replaced the query version when the query had one. The minimum Osquery version has its own `minimum_osquery_version` attribute now. The query payload also has the `pk`, `name` and `tag` attributes, and the compliance check of the query. This payload is a part of the `osquery_pack_query_update` events.


#### 🧨 PATCH on the Monolith API

`PATCH` gives a `405 Method Not Allowed` on the Monolith catalog, condition, enrollment and manifest enrollment package endpoints. Use `PUT`, and send all the attributes of the object.

#### 🧨 Inventory JMESPath compliance check events

The `inventory_jmespath_check_created`, `inventory_jmespath_check_updated` and `inventory_jmespath_check_deleted` events do not exist anymore. The JMESPath compliance checks publish `zentral_audit` events, like the other objects. A probe or a query on the three event types must use `zentral_audit` with the `inventory.jmespathcheck` model. The events are still linked to the compliance check and to the JMESPath check, so the events page of a check does not change. The `inventory_jmespath_check_status_updated` event does not change.

#### 🧨 Santa enrolled machines metrics

`zentral_santa_enrolled_machines_total` and `zentral_santa_enrolled_machines_sync_total` are replaced by `zentral_santa_enrolled_machines_bucket` and `zentral_santa_enrolled_machines_sync_bucket`, which have an `le` label. The `le="+Inf"` bucket gives the value of the two removed gauges: in a dashboard or an alert, change the metric name and select that bucket. A query that sums the buckets counts each machine seven times.

#### 🧨 Santa compiler rules on team ID and certificate targets

A rule with the `ALLOWLIST_COMPILER` policy is rejected on a target that is not a cdhash, a binary or a signing ID, in the web console, the rule API and the ruleset API. The Santa client only accepts the compiler state on those three rule types. On a team ID or a certificate it drops the rule when it evaluates it, so the rule synchronized cleanly and then left its target with no rule at all, which blocks the target in lockdown mode. The rules already in the database keep their policy, but Zentral rejects each of them at the next write: a ruleset that you post again, a `PUT` on the rule API, a Terraform configuration that you apply again, and a change to any other attribute of the rule in the web console.

#### 🧨 Privilege escalation hardening — task results

A task belongs to the user or the service account that launched it, and `/api/task_result/<task_id>/` and `/api/task_result/<task_id>/download/` answer only for that principal. A superuser reads all of them, as before. Until now the two endpoints only asked for a valid session or API token: any authenticated principal that had a task ID could read the state of that task and download its file, and an export carries everything the principal that launched it was allowed to see. The state endpoint gives the `UNKNOWN` status for the task of a different principal, like it does for a task that does not exist, and the download endpoint gives a `404`. The task list and the task pages of the web console already applied this rule.

A task that a device launched, and a task that Zentral launched before version 2025.11, has no user, so only a superuser can read those. The exports are temporary: launch the export again to get a file that you can download.

#### 🧨 PBAC User action groups

The `UserActions` action groups contain the view actions of the models now. A role with a permit on `Action::"GlobalUserActions"`, or on the `UserActions` group of one namespace, reads the pages and the API endpoints of the models in that scope. Review your policies before you update.


### Bug fixes


The task that pushes an updated DEP profile to Apple Business Manager belongs to the user who saved the enrollment now. It was the only task that a user launched with no record of the user, so it was not in the task list of that user, and only a superuser saw its result.

A retried task does not write an error to the logs about its user record anymore. Celery publishes a retry with the same task ID, Zentral tried to write the record a second time, and the unique constraint refused it. The task that assigns the default enrollment of a DEP virtual server retries when Apple throttles it.

The task list of the web console reads the user of each task together with the tasks now. It made one more query for each row of the page, and a superuser sees the tasks of all the users.

The notifier sets a connect timeout, a socket timeout and a health check interval on its Redis client now. Without the timeouts the socket stays in blocking mode: a Redis server that stops answering and does not close the connection, a managed Redis during a failover for example, blocked a notification for ever in the middle of a web request. The health check interval covers the listener thread, which reads only, and which stayed silent for ever on the same connection because a read that times out there does not give an error. The listener sends a periodic PING now, and the write that fails is what makes the notifier reconnect. Zentral applies configuration changes on the probes, the event stores and the Monolith repositories again after this failure, and not only after a restart.

The event store cache expires after 300 seconds now. A notifier notification was the only thing that made an instance load it again, so an instance that did not get one kept the store configuration it read when it started, and sent events to a store an operator had already changed. The Cedar policies cache had this protection, the store cache did not.

The probe caches expire after 300 seconds now. A notifier notification was the only thing that made an instance load them again, so an instance that did not get one matched events against the probes it read when it started. Some probe views are built from another view. Such a view follows the version of the view it is built from, and not an age of its own, so 300 seconds is the delay for all of them.

A store worker verifies the configuration of its store every 300 seconds now. Before, only a notifier notification made the worker apply a change, and the notifier does not guarantee delivery. A worker that did not receive the notification kept the event filters and the credentials from its start, and an operator had to restart it. The worker now stops when it finds a change to its store, and starts again with the configuration in the database.

Fixed the `zentral_audit` events of the Santa enrollments and the Santa enrolled machines, which were not linked to the object they report. A model that declares the parents of an object replaced the link to the object itself, and the events of that object did not reach its page. A model keeps control of its own key when it declares one, because the MDM commands are linked by UUID and not by primary key.

Fixed the version of an Osquery query in the events published when a user changed the query from the web console. The version was a database expression, and not a number.

Fixed the `zentral_audit` event published when a user increases the version of an enrollment. The enrollment payload had no version, so the event showed the same value before and after the change. The payload has the `version` and `updated_at` attributes now, for the Monolith, Munki, Osquery, Santa and Turbo enrollments.

Fixed the version of a Munki script check that increased on every API update: the excluded tags were compared with the included tags. A new version makes every machine in scope run the check again.

Fixed the Santa machines reported out of sync when a rule of the current sync session replaced a rule they already had. The ledger keeps the rule the client confirmed until it confirms the replacement, and a lost session returns to it.

Fixed a Santa rule added and removed during the same sync session: a lost session recorded it as held by the machine. The machine then stayed out of sync until a clean sync.

The Santa sync operations of a machine are serialized on its enrolled machine row lock now. A rule download that Santa retried could overlap the initial request and skip a batch of rules. A rule download also uses the sync session of a concurrent preflight.

Fixed the Santa preflight that overwrote what another request committed on the same enrolled machine: it saved every column of the row it read. Only the attributes the client reports are written now.

The inventory history cleanup deletes in bounded batches now. One unbounded statement for each table could delete millions of rows in one transaction, and keep the database at its maximum capacity for the full run. Each batch is a transaction, and a batch that gives an integrity error is retried alone.

Fixed the MDM devices list that moved devices between its pages: it sorted on the last seen timestamp, which is null until a device checks in. The sort includes the primary key now.

Fixed nine MDM API list endpoints that ignored the `ordering` query parameter: the enrolled devices one and the eight artifact ones. The queries had no `ORDER BY`, so a client that read the pages could miss rows and get others two times. The seven endpoints of an artifact version order on the artifact version timestamps now. Each endpoint also orders on the primary key.

Fixed an MDM blueprint that serialized its artifacts in a different order on each update of the same data. The artifacts of a blueprint, the artifacts an artifact requires and the artifacts a declaration references were read without an order. That order was the installation sequence of the devices, and the order of their declaration items. The required and the referenced artifacts are sorted by name now, and a blueprint keeps the order in which its artifacts were added.

The file of a deleted MDM data asset is removed from the storage now. Every version that was deleted, alone or with its artifact, kept its file in the storage.

Fixed an MDM data asset update that was rejected when it kept the same file: the check against the latest version of the artifact included the version to update. An update of only a platform, a shard or a tag compared the asset with itself.

The MDM data asset API accepts only XML property lists now, like the upload form. A binary property list was accepted, then stored and given to the devices as `text/xml`. An upload that used this is rejected now.

A malformed base 64 source on the MDM profile and provisioning profile API endpoints gives a 400 now, and not a 500.

The MDM data asset and enterprise app APIs give a generic message when they cannot download the file now, like the package API already did. The message of an error from S3 can contain the bucket, the key, the region or the state of the credentials. Zentral writes it to its logs instead. The messages about the file extension, the URI scheme and the hash are unchanged.

Fixed an MDM software update enforcement in latest mode that took a device out of management when it had no update to enforce. The `tokens` and `declaration-items` check-ins and `/connect` gave a 500, and the device stopped receiving all of its declarations. A device above the *Maximum target OS version* was enough to cause it, and so was a deployment that never synchronized the Apple software lookup service. Zentral leaves the configuration out of the declarations it serves now, and writes a log message.

Malformed MDM client capabilities do not take a device out of management anymore. The lookup of the supported status items failed on a type, and the `tokens` and `declaration-items` check-ins and `/connect` gave a 500. The status subscriptions use the items that all the clients support now, and Zentral writes a warning.

An MDM re-enrollment completes on the token update of the device now. The re-enrollment profile carries the payload identifier of the profile it replaces, so the device updates its MDM payload and sends no authenticate. Zentral waited for that authenticate: the session stayed in the started state, the check-in gave a 500 with no event on each token update, and the certificate expiry date that starts the next re-enrollment was never written, so the device re-enrolled every four hours. A token update writes that date now. An authenticate on a session that is already authenticated is still refused, with a 400 and an event that carries the status of the session, and not a 500.

The MDM software update enforcement API rejects a null delay in days or local time when a maximum target OS version is set. A latest enforcement needs both fields to calculate the target date of its declaration. If you omit them, the defaults of 14 days and 09:30 apply, as before.

Fixed the scope of a Monolith sub manifest package that uses the *Default Installs* key. Zentral put the package in the `default_installs` of every machine, and ignored the excluded tags and the shards. A machine out of scope kept a self-serve entry that can install the package later, with no request from the user. The web console form also removed the excluded tags and the shards from a package that uses the *Managed Updates* key.

The Osquery enrollment package finds the `osqueryd` binary at installation time now, and writes its path in the launch daemon. It looks at the standard location, `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`, then at the location of the Fleet orbit agent, `/opt/orbit/bin/osqueryd/macos-app/stable/osquery.app/Contents/MacOS/osqueryd`, then at the `/usr/local/bin/osqueryd` symbolic link. Before, the launch daemon always started `/usr/local/bin/osqueryd`, and the package made that symbolic link only for the standard location. On a machine with osquery in a different place, the installation reported no error and the daemon did not start. The installation stops with an error now if it finds no `osqueryd` and the package includes none.

Munki installs the Osquery enrollment package again when `osqueryd` moves, and when the `pro.zentral.osqueryd` launch daemon is not present or does not run. The postinstall script writes the path that it found in `/usr/local/zentral/osquery/enrollment.plist`, and the installcheck script of the pkginfo compares it with the path on the machine. The installcheck script makes these tests only if it finds an `osqueryd`, because the installation stops without one.

Munki installs the Osquery enrollment package on a machine that has the Turbo agent now. The installcheck script of every enrollment package stopped the installation if `/opt/zentral/lib/Turbo.app` was present. Only the Munki enrollment package makes this test now, because the Turbo agent runs the Zentral preflight and the postflight itself.

The `rebuild_manifest_enrollment_packages` command takes a `--manifest` option with one or more manifest IDs now, to rebuild the enrollment packages of a part of the manifests only. It also takes a `--new-version` option, which increases the version of each enrollment package that it rebuilds, and gives it a new filename. The enrollment versions do not change with it, so the machines that are up to date do not install the packages again.

Fixed the links of the Santa cdhash event store redirect, which had the Signing ID target type. The view sends the user back to the events page of the target when the store gives no event URL. It sent them to the Signing ID events page instead, with a cdhash identifier that this page cannot find. The events the view read were the correct ones.


## 2026.5


### Features


#### Core

The pages launching a background task report its outcome now, instead of reloading as if nothing had happened.

The messages are stuck to the top of the page, so a task launched from a button far down a page still reports where it can be seen.

The remaining background tasks are attributed to the user who started them, so they show up in their task list.

The PBAC policy sets are parsed once and cached.

The linked compliance check and job ids are exposed on the API serializers.

#### Inventory

The macOS app instances carry the Apple code signing information now — team id, executable path, cdhash, entitlements and the two signing times — on the machine page, in the full JSON export and in the per-machine CSV one.

Reworked the machine macOS app instances list into a collapsible detail view.

Committing a machine snapshot tree makes far fewer queries: the subtrees are prefetched in bulk instead of being looked up once per occurrence.

#### MDM

Recovery password configurations can schedule a password rotation after each reveal of the password, like DEP enrollments already do for the auto admin password.

FileVault configurations can schedule a PRK rotation after each reveal of the PRK.

Synchronizing a DEP virtual server with Apple Business Manager now posts a `dep_device_change` event for every device it changed, with the previous and the new value of the record, like an audit event.

The command creations, the device blocking, the artifact, blueprint artifact and enrollment changes, the push certificate, DEP token and Apps and Books location changes, and the DEP virtual server connection are audited now. No key material reaches the events.

Assigning an enrollment profile to a DEP device via the API posts an audit event, like the web interface already did.

The APNs notifications an operator asks for carry the request context, so an operator poke can be told from one Zentral decided on by itself.

A queued command is verified again just before it is delivered, since the device state can change while it waits.

The default DEP enrollment is assigned in a background task, chunked, and the assigned devices are read back from Apple instead of being guessed.

The DEP requests are sized from the limits the account detail advertises.

New `refresh_apps_books_asset_metadata` management command, for the assets created without their metadata.

The enrollment used is reported in the enrollment request events, and in the re-enrollment ones. The DEP and user enrollment payloads gain the realm, and the DEP one the enrollment secret.

#### Monolith

Repository syncs now run in the background. Repositories that need more than the request timeout to sync are supported, and concurrent syncs of the same repository are prevented.

#### Munki

The Munki enrollment package is skipped when the Turbo agent is installed.

A machine polling `job_details` without ever completing a run is not invisible server side anymore.

#### Osquery

The identical records of a status log upload are collapsed into one event carrying a `count`, and the number of events one upload can produce is bounded.

#### Santa

The rules of a sync are only recorded once the client confirms them in its postflight. A sync the client never confirms is settled during the next preflight, and its rules are sent again.

One request less per rule download: the last batch does not need to be acknowledged anymore.

New `santa_postflight` event, reporting what the client confirmed. Heartbeat, like the preflight event.

The preflight event reports the sync session, the result of the rule comparison and the reason for a clean sync.

The configuration is reported in every Santa event that has one, and links the event to it.

New `zentral_santa_enrolled_machines_sync_total` and `zentral_santa_active_machines_bucket` metrics.

The result of the last rule comparison and the sync stage timestamps are displayed on the machine page.

#### Turbo

New module for Turbo, the MDM-deployed Zentral agent running scripts and mSCP compliance checks on the macOS devices.

Recurring and one-time job schedules on a job anchor, with a per-machine result ledger.

Management UI and API for the configurations, enrollments, scripts, mSCP checks and jobs, the agent protocol endpoints, the script and mSCP compliance checks, and the agent request and result events.


### Backward incompatibilities


#### 🧨 API endpoint PATCH

The audited API endpoints answer a `PATCH` with a `405`. Zentral only does full updates — several serializers assume every declared field is present, which a partial update breaks. Use `PUT`.

#### 🧨 Event payload datetimes and UUIDs

The datetimes and UUIDs that were not serialized at their source reached the stores that dump the event themselves (ClickHouse, Splunk, Panther, …) wrapped in a `{"__type__": …, "__value__": …}` envelope, where Elasticsearch and OpenSearch got the plain string. They are ISO 8601 and UUID strings everywhere now. Queries and probes reading the two envelope subpaths need to be updated.

#### 🧨 Preprocess worker upgrade order

The raw events over 16KB are compressed now, and a preprocess worker still on the previous release drops the ones it receives. Restart the preprocess workers before the web workers.

#### 🧨 MDM API endpoint pagination

The API endpoints for the ACME issuer, SCEP issuer, FileVault configuration, recovery password configuration, software update enforcement, OTA enrollment, blueprint, blueprint artifact, location, location asset and push certificate lists are paginated now. Remember to upgrade the Terraform Provider.

#### 🧨 MDM DEP token audit event payload

The DEP token audit events do not carry the `has_expired` and `expires_soon` booleans anymore. They were computed when the event was serialized, and never refreshed afterwards, so a stored event kept reporting the state of the token at the time it was written. Use the `access_token_expiry` timestamp, which is still in the payload, and compare it with the event `created_at`. Probes keyed on the two removed fields need to be updated.

#### 🧨 MDM DEP virtual server device sync task result

In the result of `/api/mdm/dep/virtual_servers/<int:pk>/sync_devices/`, `operations` gains `unchanged` and `marked_deleted`, `updated` only counts the devices whose record changed, and a `status` of `SUCCESS` or `SKIPPED` is added. Read `created + updated + unchanged` for the number of devices Apple reported.

#### 🧨 MDM DEP device profile assignment time

`profile_assign_time` stays null until a synchronization brings back the value Apple recorded. It used to be set to Zentral's clock as soon as Apple answered, which is a different value.

#### 🧨 Monolith repository sync API endpoint

`/api/monolith/repositories/<int:pk>/sync/` launches a background task instead of syncing the repository during the request. It responds with `201` and a `task_id`/`task_result_url` pair, in place of the `200 {"status": 0}` and `500 {"status": 1, "error": "…"}` responses it used to return. Poll `task_result_url` to know the outcome of the sync.

#### 🧨 Osquery status log events

The identical records of a status log upload are collapsed into one event carrying a `count`. Sum `count` instead of counting the events to get the number of lines the clients sent.

#### 🧨 Privilege escalation hardening — OIDC API token issuers

An issuer mints API tokens for its service account, so adding or changing one now requires the requester to hold every role of that account — otherwise the permission was a way around the rule that a non-superuser cannot grant a role they don't hold. Viewing and deleting issuers are unaffected. A service account a PBAC policy names directly — `ServiceAccount::"<pk>"`, active or not — is superuser-only; move those grants to a role to delegate it again.

#### 🧨 Privilege escalation hardening — service account API tokens

Creating or updating a service account's API token now requires the requester to hold every role of that account, like the issuers above. Deleting a token is unaffected, and so are your own tokens.

#### 🧨 OIDC API token issuer CEL condition required

An issuer without a CEL condition accepted every identity token its provider signed for the configured audience. The condition is mandatory now, and an existing issuer without one is refused at exchange time. Set one — `claims.sub == "…"` is the usual shape — on every issuer before upgrading, or its clients stop getting tokens.


### Bug fixes


The `Authorization` header, the cookies and the MDM signature are not written to the JSON logs anymore. Django logs the request on every 4xx it reports, so a `401` on a public endpoint wrote the credential the client just failed to authenticate with to stdout.

Fixed the loss of the raw events too big for the queue: a machine snapshot tree carrying a full app inventory was rejected, and took the events it was batched with down with it. They are compressed with zstd, and the SQS batches are split by size.

Fixed multiple races under threaded workers: the probe cache deadlock, the JMESPath compliance check cache, the MDM certificate issuer cache, the Apps and Books client cache, the event producer initialization and the event queue shutdown.

The database connections are health checked and capped with a connect timeout, and recycled by every preprocessor on a recoverable error. A connection dropped by a pooler used to fail every following check-in until the worker was restarted.

Fixed the ClickHouse JSON columns deserialization: the payload paths without a sub column were displayed as raw bytes.

Fixed several machine snapshot commit failures: duplicated subtrees, concurrent version races, serialized datetimes, string `last_seen` values, empty JSON values, an in-band `mt_hash` key and certificates with non-canonical extensions.

A machine snapshot tree that cannot be committed because of a data error is dropped with a log line, instead of crashing the preprocess worker on every redelivery.

A committed object whose hash does not match is rolled back, instead of being left behind in a table where the hash is the identity.

Fixed a 500 error on bulk machine tag changes made through the API with an expiring token.

Fixed the MDM DDM declaration fetches answered with a `400` when the scope of the target changed between the token response and the fetch.

Fixed the MDM DDM status report 500s when a device reports the same artifact version under two server tokens.

Fixed the MDM `awaiting_configuration` lifecycle for the DEP enrollments awaiting the device configuration, and purge the DDM sync state with the rest of the state.

The MDM managed and enterprise app install polling backs off exponentially. It used to give up after a couple of minutes, leaving the target artifact awaiting confirmation forever.

The Apps and Books asset metadata is looked up in the storefront of the location, and not in the US one, so the assets that are not sold there get a name, a bundle id and an icon.

An MDM device blocked through the API is notified, like the web interface already did, so it is released immediately instead of at its next check-in.

The escrowed key is collected sooner when an MDM FileVault rotation does not return one.

The MDM DEP web enrollment shows an error page when the Setup Assistant issues the navigation without the device info header.

An MDM DEP synchronization does not wait on the advisory lock anymore: it reports `SKIPPED` instead of parking a worker and an open transaction for ten minutes.

`updated_at` is bumped when an MDM DEP device is written in bulk, so a client paging the API on it does not miss what a synchronization changed.

The `full_sync` parameter of the MDM DEP virtual server sync endpoint had no effect.

Monolith repository syncs launched via the API now refresh the caches, like the ones launched in the UI already did.

Fixed the Munki active machines and installed pkginfos metrics: they were built on a timestamp that moved on any write, so forcing a full sync on a long dead machine dropped it into the youngest bucket. Both follow the last postflight now.

The compliance check id of an osquery query is cleared in the response to the request that disabled it.

Fixed the Santa clean syncs, performed as normal syncs by the clients from 2024.6 on: the sync type of the preflight response was sent lowercase. Expect the machines asking for one to rebuild their rule database after the upgrade.

Fixed the Santa rule ledger being dropped during a clean sync for the machines that kept all their rules.

Fixed the Santa rule comparison: the counts missing from a preflight request are reset, the client transitive rules are not counted as synced binary rules, and a clean sync is not forced on the machines that simply have no rule.

Fixed the Santa sync incidents: an unknown severity broke the event pipeline, every clean sync opened one, the incident of a re-enrolled machine could never be closed, and an enrollment could close the incident of a machine with another serial number.

The result of the Santa rule comparison is recorded on every preflight, and not only on the configurations with a sync incident severity.

A Santa sync incident is updated when the severity is raised on the configuration while a machine is out of sync.

Santa ballot events link every configuration their votes name, and not only the last one.

The Santa preflight response falls back to a stable non matching path regex when a configuration has none. A fresh random one was sent on every full sync, and the clients flush all their decision caches whenever a path regex changes, twice per sync in this case.

`santactl doctor` does not report a broken sync connection on a healthy server anymore.


## 2026.4


### Features

#### Core

New Policy-Based Access Control (PBAC): role permissions are now expressed as Cedar policies.

Upgraded to Python 3.14 — expect some performance improvements.

#### Inventory

Added facet search for tags on the machine list — multiple tag filters now compose with AND.

#### MDM

New Package artifact to distribute installer packages, served directly by Zentral, manageable via the API.

Queued device commands can now be deleted via the API and in the UI before they are sent to the device.

Schema updates based on the 2026 Seed 1 Apple device management release.

Added `zentral_mdm_target_artifacts_bucket` metrics.

Added a Beta enrollment tokens section on the DEP virtual server detail page that fetches the organization's AppleSeed for IT tokens from Apple.

#### Munki

New public endpoint to fetch the enrollment information, authenticated with the enrollment secret.

The script check name was added to the job details payload.

### Backward incompatibilities

#### 🧨 Legacy role permissions replaced by PBAC policies

Permissions cannot be managed on the roles anymore, neither in the UI nor via the API. Use PBAC policies instead.

#### 🧨 API format suffix routes removed

The optional `.json` format suffix routes were dropped from the API endpoints.

#### 🧨 Business unit tags removed

Tags cannot be applied to all the machines in a business unit anymore.

#### 🧨 Monolith catalogs API endpoint pagination

The API endpoint for the monolith catalog list is paginated now. Remember to upgrade the Terraform Provider.

#### 🧨 Privilege escalation hardening

Granting the superuser status and managing the PBAC policies now require a superuser logged in with a local session.

Non-superusers can only grant a user or service account a role they belong to themselves. Removing existing memberships is unaffected.

#### 🧨 Inventory export tags column

The "Tags" column in the inventory export now matches the UI badges via `str(tag)` — taxonomied tags appear as `taxonomy: name` (e.g. `env: prod`) instead of the plain `name` (or `mbu/name`) the previous export emitted.

### Bug fixes

Replaced slow Santa `zentral_santa_targets_*`  metrics with `zentral_santa_target_states` metrics.

Fix MDM tagging issue when multiple enrollment sessions exist on the same device, some authenticated, some unauthenticated.

Fixed a shutdown hang in the AWS SNS/SQS workers.

Fixed a threading issue in the Jamf event preprocessor.

Fixed the Munki postflight duplicated app instance issue.

Fixed the Munki report sorting when mixing naive and aware datetimes.

Fixed the osquery CPU count collection in the system info.

Orphaned Google Workspace machine tags are now removed when the user leaves all mapped groups.

Multiple fixes in the ClickHouse event store event fetch.

Fixed the XLSX inventory export crashing when a worksheet name (e.g. a tag, app or compliance check name) contained characters Excel forbids in sheet names (`[]:*?/\`).

## 2026.3

### Features

#### Osquery

Filter out status logs with INFO severity level.

#### Santa

Added support for the file access events.

### Bug fixes

Fixed potential SCIM machine tagging conflict.

Fixed S3 Munki repository PkgsInfo iteration when using a prefix. This only affected repositories without catalogs.

Fixed Windows network interface info collection via osquery.

## 2026.2

### Features

#### Core

Add detail & list read-only views for probe actions.

Add optional CEL transformation to the HTTP Post action backend.

Better copy-to-clipboard handling for secrets.

Add OIDC API token issuer to exchange signed JWTs for short-lived API tokens.

#### Inventory

Remove tag name length constraint.

#### MDM

The current device lock PIN for the MDM enrolled devices is now stored and can be retrieved in the UI.

Add Provisioning Profile artifacts

HTML templates of enrollment custom view can now be downloaded in the detail view of the enrollment custom view.

MDM enrolled devices can now be filtered by the short name of the referenced user in the api
and the email of the realm user used in the responding enrollment session.

The MDM enrolled device API endpoints now include the realm user details when the latest enrollment session was authenticated.

#### Monolith

New fallback catalog aggregation if no catalog is provided in S3 bucket.

#### Santa

Support for the [custom_url](https://northpole.dev/features/binary-authorization/#rule-dictionary-format).

### Backward incompatibilities

#### 🧨 MDM artifacts API endpoints pagination

The API endpoints for the MDM artifacts are paginated now.

#### 🧨 Legacy inventory clients removed

Legacy inventory clients for Filewave, Sal, Watchman were removed.

### Bug fixes

The API token expiry in the events metadata was not serialized to and deserialized from an ISO 8601 string.

The missing Windows builds were added to better detect and display Windows 11 versions.

## 2026.1

### Features

#### Core

New API token format with fixed prefix `ztlX_` and checksum.

API tokens can have a name and an expiry now. Multiple API tokens can be created for a given user or service account.

New S3 Parquet event store (write only).

Better batch processing for AWS queues.

#### MDM

New `distribute_tls_chain` option (defaults to `true`) in the MDM app config to control the inclusion of the configured TLS chain in the MDM enrollment payloads.

New API endpoints to manage the MDM DEP enrollments and the custom pages.

Schema updates based on the v26.2 apple device management release.

#### Monolith

More Audit Events for the monolith module resources.

#### Google Workspace

New authentication via GCP service accounts for the Google Workspace module. Easier to configure when Zentral is deployed in private GCP accounts.

### Bug fixes

Fixed DEP device sync issues when same device is moved between two DEP virtual servers.

New lock to avoid concurrent DEP device syncs.

Configuration Profile reported without Payload UUID can now be saved in the inventory.

MDM Artifact detail pages are not slow anymore when multiple versions are deployed to 10000s of devices.

Fixed mass-tagging API error in `SET` operations.

## 2025.12

### Features

Add FileVault & encryption statuses to inventory disk table.

Add disks to inventory full export.

Google Workspace connection with group tag mappings.

ClickHouse store for admin console use (beta).

### Bug fixes

Fixed slow MDM Artifact deletion check.

Fixed slow MDM APNS device and user notification queries.

Fixed `managed_updates` filtering in the Monolith sub manifests.

### Backward incompatibilities

#### 🧨 macOS inventory disk information

The query to collect macOS disk information with Osquery has changed. The logical volumes (OS, Data) with their respective mount points and FileVault statuses are included now instead of the "physical" disk information.

## 2025.11

### Features

#### Core

JSON HTTP 500 responses for API and SCIM views.

#### Inventory

Add network interfaces to full export.

#### MDM

On-the-fly device apps & books license assignments work now also with raw `com.apple.configuration.app.managed` declarations when a default apps & books location is set in the blueprint.

Background task for mass-assignment of apps & books licenses.

Better apps & books locations & location assets read-only API.

Add StoreApp API.

Add blueprint option to distribute the legacy profiles via DDM.

Add Digicert - Trust Lifecycle Manager SCEP issuer backend. Support for dynamic enrollment codes.

#### Osquery

Preserve Osquery inventory result time.

#### Core

Add mechanism to link background tasks to users.

Add user and API token CRUD audit events.

### Bug fixes

Fix DDM status report response code. It should be `200`.

## 2025.10

### Features

#### MDM

Add Certificate Assets to manage the [`com.apple.asset.credential.scep`](https://github.com/apple/device-management/blob/8d9958d9b54239344e7190e17ddb559416b017e3/declarative/declarations/assets/credential.scep.yaml) and [`com.apple.asset.credential.acme`](https://github.com/apple/device-management/blob/8d9958d9b54239344e7190e17ddb559416b017e3/declarative/declarations/assets/credential.acme.yaml) DDM assets, with their respective credentials. Certificate Assets can be used for example to issue Okta device certificates via SCEP, with dynamic challenges.

Add auto admin unique passwords for ADE. This is similare to Windows LAPS.

Add last IP address to enrolled device & user records.

Return users in enrolled device API responses.

Update Apple [declaration definitions](https://github.com/apple/device-management/tree/8d9958d9b54239344e7190e17ddb559416b017e3/declarative/declarations) and [skipkeys](https://github.com/apple/device-management/blob/8d9958d9b54239344e7190e17ddb559416b017e3/other/skipkeys.yaml).

#### Core

Better background task status tracking (`PENDING`, `STARTED`).

### Bug fixes

Fix DEP enrollment update view timeout when the corresponding profile is assigned to 10000s of devices in ABM.

### Backward incompatibilities

#### 🧨 MDM auto admin password

The option to set the same auto admin password during ADE has been removed. Passwords are unique for each device now.

## 2025.9

### Features

#### Osquery

Add excluded tags when linking a pack to a configuration.

#### MDM

Add ACME and SCEP issuers. Hardware bound ACME certificates with device attestations will be used when the device and the CA are compatible. SCEP must be configured as the fallback mechanism.

Add API endpoint to send custom commands to enrolled devices.

### Bug fixes

Fix MDM realm group tagging during enrollment with multiple groups pointing to the same tag.

Fix update machine tags API when referencing an existing taxonomy tag without its taxonomy.

Fix MDM slow blueprint deletion check.

### Backward incompatibilities

#### 🧨 MDM enrolled devices API

This API endpoint is now paginated.

#### 🧨 MDM SCEP configs replaced by SCEP issuers

SCEP configurations have been replaced by SCEP issuers. The migration will take care of this but do not forget to update your Terraform provider.

## 2025.8

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

Remove Munki install probes.

#### Santa

Support for the [Santa CEL policies](https://northpole.dev/features/binary-authorization#cel).

Support for the [Santa Signing ID rules](https://northpole.dev/features/binary-authorization#signingid).

Support for the [Santa CDHASH rules](https://northpole.dev/features/binary-authorization#cdhash).

Support for the `SyncExtraHeaders` configuration key and implementation of the authentication via `Zentral-Authorization` header.

Exception portal.

#### Inventory

Jamf extensions attribute to principal user mapping.

Microsoft Intune inventory sync.

#### Events

New Zentral Audit events to track configuration changes.

New `zentral.core.stores.backends.snowflake` store backend for [Snowflake](https://www.snowflake.com/).

New `zentral.core.stores.backends.panther` store backend for [Panther](https://panther.com/)

New `zentral.core.stores.backends.clickhouse` store backend for [ClickHouse](https://clickhouse.com/)

#### One more thing…

Release of the new UI.

### Backward incompatibilities

#### 🧨 Event queues

Remove `filter_policies` from the AWS SNS/SQS queues. All events will be delivered to the queues and filtered in the workers.

#### 🧨 Event stores

Event stores are managed in the database now. You can still pre-configure them in `base.json` with the new provisioning functionality.

Removed the `excluded_event_types` and `included_event_types` options. Use the `excluded_event_filters` and `included_event_filters` options instead.

Removed the Syslog, Humio, and Azure Log Analytics event store backends.

#### 🧨 Probes refactoring

The different probe models have been removed. Only event probes are supported now. The Munki install probes were the last ones still available, and they can be easily replaced by event probes.

#### 🧨 Probe actions refactoring

Probe actions are not managed in `base.json` anymore, and a lot of action backends have been removed because they were not used. We have kept `http_post` and `slack_incoming_webhook`. Actions will have to be re-created via the API and added to the probes.

#### 🧨 MDM Profiles *NOT* managed via DDM anymore

The DDM implementation of the legacy profile declarations is not robust enough at the moment. Network disruptions might leave the device in an indesirable state that can only be fixed with a reboot. This is not good enough, especially during the MDM enrollment. We have decided to switch back to the InstallProfile command until this is fixed by Apple.

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

Splunk can be used as admin console store.

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
