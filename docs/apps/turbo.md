# Turbo

Turbo is the Zentral agent for macOS. It runs **jobs** on enrolled machines – shell scripts, and checks from the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (mSCP) – reports their results back to Zentral, and collects the machine inventory.

Unlike the munki, osquery or santa modules, Turbo is not an integration with a third party agent: the agent and the protocol described below are both Zentral's.

Results are turned into [compliance check](inventory.md#compliance-checks) statuses and machine tags, and every job run is published as an event.

## Zentral configuration

To activate the turbo module, you need to add a `zentral.contrib.turbo` section to the `apps` section in `base.json`. The module has no configuration key of its own.

```json
{
  "apps": {
    "zentral.contrib.turbo": {}
  }
}
```

## Turbo deployment

### Create a Turbo configuration

In Zentral, go to *Turbo > Configurations*, and click on the [Create] button. A configuration holds the operating parameters of the agents enrolled in it:

|Attribute|Default|Description|
|---|---|---|
|`collect_inventory`|`true`|When enabled, the agent posts a full machine inventory snapshot on the interval below.|
|`inventory_interval`|`86400` (1 day)|Inventory refresh interval, in seconds.|
|`default_check_interval`|`86400` (1 day)|Run interval, in seconds, applied to the recurring jobs that do not set their own.|
|`config_refresh_interval`|`600` (10 min)|How long the agent may trust a cached configuration before refreshing it, in seconds.|
|`results_batch_size`|`100`|Maximum number of results the agent uploads per request. A larger backlog is drained over several requests.|

All the interval attributes are expressed in seconds, and must be between 60 (1 minute) and 604800 (7 days). `results_batch_size` must be between 1 and 1000.

The agent picks up a changed configuration on its next configuration refresh – there is no payload to redistribute.

A configuration cannot be deleted while an enrollment or a job schedule still references it.

### Create an enrollment

Once you have created a Turbo configuration, you can create an enrollment for it using the [Create] button in the Enrollments section of the configuration. This is how Zentral associates machines with configurations.

#### Machine segmentation

You can pick a Meta business unit to segment your machines. You can also segment the machines during the enrollment by picking tags – they are applied to the machine when it enrolls.

#### Enrollment restrictions

Enrollments can be restricted by machine serial numbers and UUIDs – all machines are allowed if the `Serial numbers` and `UUIDs` fields are left blank. You can also set a maximum number of enrollments – machines will always be allowed if the `Quota` field is left blank.

#### Save and download

Save the enrollment form, you will be redirected to the configuration, and the new enrollment will be available. You can download two different versions of the enrollment:

 * a plist containing only the Turbo specific configuration keys. This plist can be uploaded to Jamf, to create a custom settings payload for the `com.zentral.turbo` preference domain.
 * a signed configuration profile with a `com.zentral.turbo` custom settings payload, that can be further customized or distributed as is.

Both carry the same two managed keys:

|Key|Description|
|---|---|
|`BaseURL`|The Zentral TLS hostname. The agent appends `public/turbo/` to it itself.|
|`EnrollmentSecret`|The secret of the enrollment, exchanged for a per-device token at enroll time.|

Bumping the version of an enrollment (the [Bump Enrollment] button) does not change the secret – it is a signal for the agents, which poll the [enrollment info endpoint](#publicturboenrollment) and can react to a bump. Updating an enrollment through the API bumps its version too.

### How the agent enrolls

The agent posts its serial number, its hardware UUID and the `EnrollmentSecret` to the [enroll endpoint](#publicturboenroll), and gets a per-device token back. That token authenticates every subsequent request, in an `Authorization: TurboEnrolledMachine <token>` header.

Zentral only stores the SHA-256 hash of the token: the plaintext is returned once, at enroll time, and cannot be recovered afterwards. Enrolling again mints a new token and invalidates the previous one – a machine holds exactly one valid token at any time.

A machine can be moved to a different configuration by simply deploying a different Turbo payload. Since its per-machine job history and its Turbo compliance statuses belong to the configuration it is leaving, both are dropped when it re-homes; they are rebuilt from the new configuration's jobs as results come in.

Enrolled machines are listed under *Turbo > Enrolled machines*, with the date they were last seen and the state of every job that has been delivered to them.

## Jobs

A **job** is what Turbo runs on a machine. There are three kinds:

 * a **script** – a zsh script, whose exit code is the outcome,
 * an **mSCP check** – an mSCP rule, whose check logic and baseline defaults are bundled in the agent,
 * a **command** – something to collect from the machine, uploaded as one or more files.

Creating a script, an mSCP check or a command only *defines* the job. It does not run anywhere until it is scheduled in a configuration, as a [recurring job](#recurring-jobs) or a [one-time job](#one-time-jobs). The same definition can be scheduled in several configurations.

### Scripts

Go to *Turbo > Scripts* and click on the [Create] button.

|Attribute|Description|
|---|---|
|`name`|A unique name.|
|`source`|The zsh script. Exit 0 means OK, exit greater than 0 means FAIL.|
|`arch_amd64` / `arch_arm64`|Compatibility gate – whether the script may run on Intel, on Apple Silicon, or on both. At least one is required.|
|`min_os_version` / `max_os_version`|Compatibility gate – the macOS version range the script may run on. Leave blank for no bound.|
|`tag`|Optional. See [Tagging](#tagging).|
|`compliance_check`|Optional. See [Compliance checks](#compliance-checks).|

The architecture and OS version attributes are a *compatibility* gate – "can this script run here at all" – and they are evaluated by the agent. *Where* a script runs is a property of its schedule, not of the script. See [Job scope](#job-scope).

A script cannot be deleted while it is scheduled in a configuration.

### mSCP checks

Go to *Turbo > mSCP checks* and click on the [Create] button.

An mSCP check names an mSCP rule, and says which Organization Defined Value (ODV) the agent should use for it.

|Attribute|Description|
|---|---|
|`rule_id`|The mSCP rule identifier, for example `os_gatekeeper_enable`.|
|`baseline`|Optional. An mSCP baseline key, for example `cis_lvl1` or `stig`. The agent uses that baseline's default ODV for the rule.|
|`odv_int` / `odv_string` / `odv_bool`|Optional. A fixed ODV, pinned to a value of that type.|

A rule has at most one ODV, and `baseline` and an explicit ODV are mutually exclusive. There are therefore three ways to configure a check:

 * a `baseline` – the agent uses that baseline's default ODV for the rule,
 * one of the `odv_*` attributes – the agent uses that value,
 * neither – the agent uses its own recommended default for the rule.

The rule identifier, the baseline and the ODV together form the identity of a check: `os_gatekeeper_enable` under `cis_lvl1` and the same rule with a pinned ODV are two different checks. The ODV is typed, so `odv_int` = 1, `odv_string` = "1" and `odv_bool` = true are three distinct identities too.

An mSCP check *is* a compliance check – one is created with it, named after that identity, and there is no toggle. The check logic itself, and the baseline defaults, are bundled and signed in the agent, not stored in Zentral.

An mSCP check cannot be deleted while it is scheduled in a configuration.

### Commands

A command collects something from a machine and uploads it. Unlike a script or an mSCP check, a command has no compliance role and produces no verdict — it produces one or more files.

Commands are created with the [API](#apiturbocommands), not in the web console. *Turbo > Commands* lists them and shows what each one collects. This is the same shape as the event stores and the probe actions: the kind decides which options the command takes, and the API validates them.

|Attribute|Description|
|---|---|
|`backend`|Which kind of command this is. It cannot be changed after the command is created.|
|`name`|A unique name.|
|`description`|Optional.|
|`<backend>_kwargs`|The options for that kind. A kind with no options does not need this attribute.|

Two kinds are available:

|Kind|Collects|Options|
|---|---|---|
|`sysdiagnose`|A `sysdiagnose` archive.|None. The agent runs the tool unattended and uploads the archive it produces.|
|`file_export`|The files that match a list of path patterns, plus a manifest of what was collected.|`patterns` and `max_size`, below.|

The `file_export` options:

|Option|Description|
|---|---|
|`patterns`|1 to 32 absolute path patterns, for example `/var/log/install.log*`. Each one is at most 1024 characters, must start with a `/`, and must not contain a `..` segment or a `**`. See the syntax below.|
|`max_size`|The maximum **uncompressed** total, in bytes. 104857600 (100 MB) by default, 524288000 (500 MB) at most. File sizes are known before anything is written, so the agent decides what to include first, in a stable path order, and reports what it skipped.|

The agent matches the patterns with `fnmatch`, which macOS provides. The syntax is the shell glob syntax, with one important limit:

|Pattern|Matches|
|---|---|
|`*`|Any sequence of characters, up to the next `/`. `/var/log/*` matches `/var/log/install.log`, and does not match `/var/log/sub/deep.log`.|
|`?`|Any single character.|
|`[abc]`|One character of the set.|

**There is no recursive wildcard.** `fnmatch` reads `**` as a single `*`, so `/Library/Logs/**/*.log` would match `/Library/Logs/a/b.log` and not `/Library/Logs/a/b/c.log` — one level, not every level. Zentral refuses a pattern that contains `**`, because a pattern written for recursion would otherwise collect one level and give no error. Name each level you want instead:

```
/Library/Logs/Foo/*.log
/Library/Logs/Foo/*/*.log
/Library/Logs/Foo/*/*/*.log
```

A `file_export` run produces two files: a manifest, which lists what was matched, collected, skipped and unreadable, and an archive of the collected files. The manifest is a separate file so an operator can read what a run collected without downloading the archive. A run that matched nothing uploads the manifest and no archive.

**A command runs one time only.** It cannot be attached to a recurring job — collecting the same files every hour is a log shipper, not a job. Schedule it with a one-time job, or with the *Schedule one-time job* action on a machine page.

Every command carries the *changing the version re-runs the job* behaviour of the other kinds: editing the options bumps the version, and the agent runs the command again. Renaming it does not.

A command cannot be deleted while it is scheduled in a configuration.

### Recurring jobs

A recurring job runs a definition on an interval, for as long as it stays in scope. Create one from the Recurring jobs section of a configuration, or from *Turbo > Recurring jobs*.

|Attribute|Description|
|---|---|
|`job`|The script or mSCP check to run.|
|`interval`|Run interval in seconds, between 60 and 604800. Leave empty to use the configuration's `default_check_interval`.|

A given definition can be scheduled as a recurring job at most once per configuration – to run the same script on two cadences, schedule it in two configurations. Once a recurring job exists, its definition cannot be swapped for another one, so the choices only list the definitions that are not scheduled in that configuration yet.

### One-time jobs

A one-time job runs a definition once per machine. Create one from the One-time jobs section of a configuration, or from *Turbo > One-time jobs*.

|Attribute|Description|
|---|---|
|`job`|The script or mSCP check to run.|
|`not_before`|Optional. Do not deliver the job before this date – use it to schedule a run in the future.|
|`not_after`|Optional. Delivery window end. The job is not delivered anymore after this date, whether it ran or not.|

Zentral keeps serving a one-time job to a machine until a result for the current version comes back. Until then – agent restarted, machine offline, result lost – the job is still pending for that machine. Once a result has been recorded, the job is not served to that machine again, and editing the definition afterwards does not reopen it: to run it again, create a new one-time job.

Editing the definition while a machine has not reported a result yet bumps its [version](#job-versions), and the machine gets the new version – an older run that was in flight will not close the job.

To run a one-time job on a single machine, go to *Turbo > Enrolled machines*, open the machine, and click on the [Create] button ("Schedule a one-time job for this machine"). The configuration and the serial number are set for you.

### Job scope

Both kinds of schedule are scoped the same way, and always within their own configuration:

|Attribute|Description|
|---|---|
|`tags`|Deliver to the machines carrying any of these tags.|
|`serial_numbers`|Deliver to these machines.|
|`excluded_tags`|Never deliver to the machines carrying any of these tags.|
|`excluded_serial_numbers`|Never deliver to these machines.|

**IMPORTANT:** the job is in scope if **any** tag or serial number is a match. If neither `tags` nor `serial_numbers` is set, the job is in scope for every machine of the configuration. The exclusions always win, and a machine cannot be both included and excluded – tags and excluded tags must be disjoint, and so must the two serial number lists.

The configuration and the definition of a schedule are fixed when it is created. Re-pointing an existing schedule at another configuration would retarget a whole fleet, and strand its per-machine history, so both fields are read-only afterwards – delete the schedule and create a new one instead.

### Job versions

A definition carries a version, which Zentral bumps when the definition changes: for a script, when its `source` changes; for an mSCP check, when any of its attributes changes – they are all identity-bearing.

The version is served to the agent with the job, and reported back with every result. It is how Zentral tells a run of the current definition from a run of a superseded one:

 * the agent re-runs a job whose version moved,
 * a result whose version matches the current one is scored: it updates the compliance check status, moves the tag, and closes a one-time job,
 * a result for a superseded version is still recorded and published as an event, but it does not touch the compliance status or the tag, and it does not close a one-time job.

Editing a script's name, description, tag or compatibility attributes does *not* bump the version – the script itself has not changed.

### Compliance checks

A script becomes a compliance check when its `Compliance check` box is ticked. An mSCP check always is one. The statuses appear on the machine, alongside the compliance checks of the other modules, and each transition is published as an event.

For a **script**, the status is derived from the exit code reported by the agent:

|Reported|Status|
|---|---|
|exit code 0|`OK`|
|exit code greater than 0|`Failed`|
|no exit code – the script could not run|`Unknown`|

For an **mSCP check**, the agent reports the verdict directly – Zentral cannot interpret the bundled mSCP logic – as a status code:

|Reported `status`|Status|
|---|---|
|`0`|`OK`|
|`200`|`Unknown`|
|`300`|`Failed`|
|`400`|`Out of scope` – the rule does not apply to this machine|
|`100` or an unknown code|no status is recorded|

A check that had a status and now reports `Out of scope` publishes one last status update event, then its status is dropped so it stops weighing on the machine's overall compliance.

Unticking `Compliance check` on a script deletes the compliance check and all its statuses.

### Tagging

A script can carry a tag, which follows the result of its runs:

 * exit code 0 – the tag is added to the machine,
 * exit code greater than 0 – the tag is removed from the machine,
 * no exit code, the script could not run – the tag is left as it is.

Tagging and the compliance check role are independent: a script can do both, either, or neither. Tagging is applied by Zentral from the reported exit code, so it is not part of what the agent is told about the job.

## Turbo sync

Once enrolled, the agent talks to Zentral over four endpoints under `/public/turbo/`, all authenticated with the per-device token from the enrollment:

```
Authorization: TurboEnrolledMachine the_token_string
```

There is no single "sync" request: the agent refreshes its configuration, uploads results, reports its state and posts its inventory on their own cadences. Every one of these requests is a heartbeat, and publishes a `turbo_request` event.

The agent may gzip the body of its POST requests, with a `Content-Encoding: gzip` header.

### Configuration

The agent fetches its configuration – the operating parameters and the jobs currently in scope for the machine, each with its payload, its version, and the schedule that delivered it – at least every `config_refresh_interval` seconds. See [`/public/turbo/config/`](#publicturboconfig).

### Results

The agent uploads the results of the runs it has accumulated, at most `results_batch_size` per request; a larger backlog is drained over several requests. See [`/public/turbo/results/`](#publicturboresults).

A result is correlated back to its schedule, and from there to its job, by the schedule's primary key. Each accepted result is published as a `turbo_result` event, stamped with the time the job actually ran on the device rather than the time Zentral received it – so a drained backlog lands on the timeline where it belongs.

### Status

The agent reports the jobs it currently holds, and the schedule it holds them under. Zentral reconciles its per-machine bookkeeping against that report: the jobs still reported are marked as held, the ones that are not are marked as removed. See [`/public/turbo/status/`](#publicturbostatus).

### Inventory

When `collect_inventory` is enabled, the agent posts a full machine inventory snapshot every `inventory_interval` seconds. The snapshot joins the standard [inventory](inventory.md) pipeline, under a `Turbo` source. Inventory is not a job – it is not scheduled, and it produces no result. See [`/public/turbo/inventory/`](#publicturboinventory).

Zentral always attributes the snapshot to the authenticated machine: a serial number in the body is ignored.

### Tolerant batches

The results and status endpoints validate strictly per entry, and tolerantly per batch. A body that does not match its envelope – `results` or `jobs` not being a list – is a `400`. But a single malformed entry inside a well-formed batch does not fail the request: it is set aside, and the valid entries are processed. Rejecting the whole batch would just make the agent retry the same poisoned outbox forever.

The response therefore acknowledges every entry Zentral *processed*, in two lists:

 * `accepted` – the entry was recorded,
 * `skipped` – the entry was well-formed but could not be used, with a `reason`: `unknown_schedule` (the schedule is unknown, or belongs to another configuration), `kind_mismatch` (the `kind` contradicts the resolved schedule), or `unknown_job_kind` (the job is of a kind this Zentral does not know – it can only happen to an instance still on the previous release, during a rolling upgrade, and it resolves itself when the upgrade completes).

An entry that appears in neither list was set aside as malformed. Zentral logs it; the agent deduces it from what is missing.

### Errors

The device endpoints always answer with JSON – never with an HTML error page.

|Status|Body|Meaning|
|---|---|---|
|`401`|`{"error": "unauthenticated"}`|Missing, malformed or unknown token.|
|`400`|`{"error": "invalid_enrollment"}`|The enroll body or the enrollment secret was refused. Deliberately opaque.|
|`400`|`{"error": "invalid_json"}`|The body is not a JSON object.|
|`400`|`{"error": "invalid_gzip"}`|`Content-Encoding: gzip` was set, but the body could not be decompressed.|
|`400`|`{"error": "payload_too_large"}`|The body is over the server limit.|
|`400`|`{"error": "invalid_results"}`|`results` is not a list.|
|`400`|`{"error": "invalid_jobs"}`|`jobs` is not a list.|

## Events

|Event type|Tags|Description|
|---|---|---|
|`turbo_enrollment`|`turbo`|A machine enrolled or re-enrolled. The `action` payload attribute is `enrollment` or `re-enrollment`.|
|`turbo_request`|`turbo`, `heartbeat`|One authenticated agent request. The `request_type` payload attribute is `config`, `results`, `status` or `inventory`. This is the Turbo heartbeat.|
|`turbo_result`|`turbo`|One job result. Its `created_at` is the time the job ran on the device.|
|`turbo_script_check_status_updated`|`turbo`, `compliance_check`, `compliance_check_status`, `turbo_compliance_check`|The status of a script compliance check changed on a machine.|
|`turbo_mscp_check_status_updated`|`turbo`, `compliance_check`, `compliance_check_status`, `turbo_compliance_check`|The status of an mSCP check changed on a machine.|

The enrollment info endpoint is not one of the four token-authenticated endpoints: it publishes the standard `enrollment_info_request` event instead of a `turbo_request` one.

A machine is considered overdue when it has not sent a `turbo_request` event for twice its configuration's `config_refresh_interval` – the cadence is configurable, so the heartbeat timeout follows it instead of being a fixed value.

The `turbo_request` and `turbo_result` payloads carry the enrollment and the configuration, and – for results and held jobs – the job, its schedule and its definition, so events can be correlated with the objects they came from without a database lookup.

Creating, updating or deleting any Turbo object from the web console or the API publishes a `zentral_audit` event.

## Maintenance

Zentral keeps one bookkeeping row per (machine, schedule) pair. When the agent stops reporting a job, its row is marked as removed rather than deleted – for a one-time job that row is the gate that stops it from being served again, so dropping it would re-run the job. The rows are purged by a management command:

```bash
python server/manage.py cleanup_turbo_machine_job_statuses
```

Rows removed more than 30 days ago are purged; use `--days` to change that. One-time job rows are only purged once their delivery window has explicitly closed – a one-time job with no `not_after` keeps its rows.

## HTTP API

### Requests

#### Authentication

API requests are authenticated using a token in the `Authorization` HTTP header:

```
Authorization: Token the_token_string
```

See [API authentication](core.md#api-authentication) for how to create a service account, issue a token for it and set an expiry.

#### Content type

The Turbo endpoints only accept JSON:

* `Content-Type: application/json`

#### Updates

Zentral only does full updates: use `PUT` and send every attribute. `PATCH` returns a `405`.

#### Pagination

The list endpoints are paginated. The response is an object with a `count`, a `next` and a `previous` URL, and the `results` array. Use the `limit` and `offset` query parameters to page through them – the default limit is 50, and the maximum is 500.

#### Terraform

Every Turbo object below can also be managed with the [Zentral Terraform provider](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs), which is built on these endpoints. The matching resource is linked at the top of each section.

### /api/turbo/configurations/

Terraform resource: [`zentral_turbo_configuration`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_configuration)

#### List all configurations

* method: GET
* PBAC action: `Turbo::Action::"viewConfiguration"`
* Optional filter parameter:
    * `name`: name of the configuration

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/turbo/configurations/?name=Default" \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
            "name": "Default",
            "description": "Default Turbo configuration",
            "collect_inventory": true,
            "inventory_interval": 86400,
            "default_check_interval": 86400,
            "config_refresh_interval": 600,
            "results_batch_size": 100,
            "created_at": "2026-08-20T09:23:55.152132",
            "updated_at": "2026-08-20T09:23:55.152137"
        }
    ]
}
```

#### Add a configuration

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createConfiguration"`

Example:

configuration.json

```json
{
  "name": "Default",
  "description": "Default Turbo configuration",
  "collect_inventory": true,
  "inventory_interval": 86400,
  "default_check_interval": 86400,
  "config_refresh_interval": 600,
  "results_batch_size": 100
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @configuration.json \
  https://$ZTL_FQDN/api/turbo/configurations/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "name": "Default",
    "description": "Default Turbo configuration",
    "collect_inventory": true,
    "inventory_interval": 86400,
    "default_check_interval": 86400,
    "config_refresh_interval": 600,
    "results_batch_size": 100,
    "created_at": "2026-08-20T09:23:55.152132",
    "updated_at": "2026-08-20T09:23:55.152137"
}
```

### /api/turbo/configurations/`<uuid:pk>`/

#### Get a configuration

* method: GET
* PBAC action: `Turbo::Action::"viewConfiguration"`
* `<uuid:pk>`: the primary key of the configuration

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/configurations/194a8af8-9e57-41b2-9b17-66ebc568c2dc/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "name": "Default",
    "description": "Default Turbo configuration",
    "collect_inventory": true,
    "inventory_interval": 86400,
    "default_check_interval": 86400,
    "config_refresh_interval": 600,
    "results_batch_size": 100,
    "created_at": "2026-08-20T09:23:55.152132",
    "updated_at": "2026-08-20T09:23:55.152137"
}
```

#### Update a configuration

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateConfiguration"`
* `<uuid:pk>`: the primary key of the configuration

Example:

configuration.json

```json
{
  "name": "Default",
  "description": "Updated",
  "collect_inventory": true,
  "inventory_interval": 43200,
  "default_check_interval": 86400,
  "config_refresh_interval": 600,
  "results_batch_size": 250
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @configuration.json \
  https://$ZTL_FQDN/api/turbo/configurations/194a8af8-9e57-41b2-9b17-66ebc568c2dc/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "name": "Default",
    "description": "Updated",
    "collect_inventory": true,
    "inventory_interval": 43200,
    "default_check_interval": 86400,
    "config_refresh_interval": 600,
    "results_batch_size": 250,
    "created_at": "2026-08-20T09:23:55.152132",
    "updated_at": "2026-08-20T09:23:55.159606"
}
```

#### Delete a configuration

* method: DELETE
* PBAC action: `Turbo::Action::"deleteConfiguration"`
* `<uuid:pk>`: the primary key of the configuration

A configuration referenced by an enrollment, a recurring job or a one-time job cannot be deleted.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/configurations/194a8af8-9e57-41b2-9b17-66ebc568c2dc/
```

Response (204 No Content):

```
```

### /api/turbo/enrollments/

Terraform resource: [`zentral_turbo_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_enrollment)

#### List all enrollments

* method: GET
* PBAC action: `Turbo::Action::"viewEnrollment"`
* Optional filter parameter:
    * `configuration`: primary key of the Turbo configuration

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/enrollments/ \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": 1,
            "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
            "secret": {
                "id": 1,
                "secret": "kDnyGL3w6nw2xUyD1VnS8g708hEFZz5WbGTv2bLCvKCbeeXerIMVYCtNgiXz5U2D",
                "meta_business_unit": 1,
                "tags": [],
                "serial_numbers": [
                    "012345678"
                ],
                "udids": null,
                "quota": 10,
                "request_count": 0
            },
            "version": 1,
            "enrolled_machines_count": 0,
            "configuration_profile_download_url": "https://zentral.example.com/api/turbo/enrollments/1/configuration_profile/",
            "plist_download_url": "https://zentral.example.com/api/turbo/enrollments/1/plist/",
            "created_at": "2026-08-20T09:23:55.162746",
            "updated_at": "2026-08-20T09:23:55.162748"
        }
    ]
}
```

#### Add an enrollment

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createEnrollment"`

Example:

enrollment.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "secret": {
    "meta_business_unit": 1,
    "quota": 10,
    "serial_numbers": ["012345678"]
  }
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @enrollment.json \
  https://$ZTL_FQDN/api/turbo/enrollments/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": 1,
    "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "secret": {
        "id": 1,
        "secret": "kDnyGL3w6nw2xUyD1VnS8g708hEFZz5WbGTv2bLCvKCbeeXerIMVYCtNgiXz5U2D",
        "meta_business_unit": 1,
        "tags": [],
        "serial_numbers": [
            "012345678"
        ],
        "udids": null,
        "quota": 10,
        "request_count": 0
    },
    "version": 1,
    "enrolled_machines_count": 0,
    "configuration_profile_download_url": "https://zentral.example.com/api/turbo/enrollments/1/configuration_profile/",
    "plist_download_url": "https://zentral.example.com/api/turbo/enrollments/1/plist/",
    "created_at": "2026-08-20T09:23:55.162746",
    "updated_at": "2026-08-20T09:23:55.162748"
}
```

### /api/turbo/enrollments/`<int:pk>`/

#### Get an enrollment

* method: GET
* PBAC action: `Turbo::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/enrollments/1/ \
  |python3 -m json.tool
```

#### Update an enrollment

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Updating an enrollment bumps its version. An enrollment owned by a distributor – another Zentral object that manages it on your behalf – cannot be updated here.

Example:

enrollment.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "secret": {
    "meta_business_unit": 1,
    "quota": 20,
    "serial_numbers": ["012345678"]
  }
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @enrollment.json \
  https://$ZTL_FQDN/api/turbo/enrollments/1/ \
  |python3 -m json.tool
```

#### Delete an enrollment

* method: DELETE
* PBAC action: `Turbo::Action::"deleteEnrollment"`
* `<int:pk>`: the primary key of the enrollment

An enrollment with enrolled machines, or one owned by a distributor, cannot be deleted.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/enrollments/1/
```

### /api/turbo/enrollments/`<int:pk>`/plist/

The [`zentral_turbo_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_enrollment) Terraform resource exposes this URL as its read-only `plist_url` attribute.

#### Download the enrollment plist file

* method: GET
* PBAC action: `Turbo::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o zentral_turbo_configuration.plist \
  https://$ZTL_FQDN/api/turbo/enrollments/1/plist/
```

### /api/turbo/enrollments/`<int:pk>`/configuration_profile/

The [`zentral_turbo_enrollment`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_enrollment) Terraform resource exposes this URL as its read-only `configuration_profile_url` attribute.

#### Download the enrollment configuration profile

* method: GET
* PBAC action: `Turbo::Action::"viewEnrollment"`
* `<int:pk>`: the primary key of the enrollment

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o zentral_turbo_configuration.mobileconfig \
  https://$ZTL_FQDN/api/turbo/enrollments/1/configuration_profile/
```

### /api/turbo/commands/

#### List all commands

* method: GET
* PBAC action: `Turbo::Action::"viewCommand"`
* Optional filter parameters:
    * `name`: name of the command
    * `backend`: `sysdiagnose` or `file_export`
    * `configuration`: primary key of a Turbo configuration – the commands scheduled in it

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/commands/ \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "c2f4a6b8-1d3e-4f50-9a7b-8c5d2e1f0a3b",
            "backend": "file_export",
            "name": "Install logs",
            "description": "The installer logs and Munki's",
            "sysdiagnose_kwargs": null,
            "file_export_kwargs": {
                "patterns": [
                    "/var/log/install.log*",
                    "/Library/Logs/Munki/*.log"
                ],
                "max_size": 104857600
            },
            "version": 1,
            "job_id": "8b1c9d7e-2a45-4c68-b9f0-3e6a7d4c5b21",
            "created_at": "2026-09-02T14:02:11.884213",
            "updated_at": "2026-09-02T14:02:11.884901"
        }
    ]
}
```

Only the options of the command's own kind are set – the other `<backend>_kwargs` attributes are `null`. `job_id` is the primary key of the job the command anchors – it is what a one-time job schedules. `version` and `job_id` are read-only.

#### Add a command

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createCommand"`

`backend` is required. The matching `<backend>_kwargs` attribute is required for a kind that takes options, and is not needed for a kind that takes none.

Example:

command.json

```json
{
  "backend": "file_export",
  "name": "Install logs",
  "description": "The installer logs and Munki's",
  "file_export_kwargs": {
    "patterns": ["/var/log/install.log*", "/Library/Logs/Munki/*.log"]
  }
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @command.json \
  https://$ZTL_FQDN/api/turbo/commands/ \
  |python3 -m json.tool
```

A `sysdiagnose` command takes no options:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"backend": "sysdiagnose", "name": "Support archive"}' \
  https://$ZTL_FQDN/api/turbo/commands/ \
  |python3 -m json.tool
```

### /api/turbo/commands/`<uuid:pk>`/

#### Get a command

* method: GET
* PBAC action: `Turbo::Action::"viewCommand"`
* `<uuid:pk>`: the primary key of the command

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/commands/c2f4a6b8-1d3e-4f50-9a7b-8c5d2e1f0a3b/ \
  |python3 -m json.tool
```

#### Update a command

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateCommand"`
* `<uuid:pk>`: the primary key of the command

`backend` cannot be changed. The kind is half the identity of the command on the wire, so a different kind is a different command.

Changing the options bumps `version`, and the agent runs the command again on the machines where it is scheduled. Changing only the name or the description does not.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT \
  -d @command.json \
  https://$ZTL_FQDN/api/turbo/commands/c2f4a6b8-1d3e-4f50-9a7b-8c5d2e1f0a3b/ \
  |python3 -m json.tool
```

#### Delete a command

* method: DELETE
* PBAC action: `Turbo::Action::"deleteCommand"`
* `<uuid:pk>`: the primary key of the command

A command that is scheduled in a configuration cannot be deleted.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/commands/c2f4a6b8-1d3e-4f50-9a7b-8c5d2e1f0a3b/
```

### /api/turbo/scripts/

Terraform resource: [`zentral_turbo_script`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_script)

#### List all scripts

* method: GET
* PBAC action: `Turbo::Action::"viewScript"`
* Optional filter parameters:
    * `name`: name of the script
    * `configuration`: primary key of a Turbo configuration – the scripts scheduled in it, as a recurring or a one-time job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/scripts/ \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "e6479cde-e17e-4f56-940e-7ccd59211c1a",
            "name": "FileVault enabled",
            "description": "Check that FileVault is on",
            "source": "/usr/bin/fdesetup isactive",
            "tag": 1,
            "arch_amd64": true,
            "arch_arm64": true,
            "min_os_version": "14",
            "max_os_version": "",
            "version": 1,
            "job_id": "70739ffd-b8f0-46ed-b8df-a0749a759779",
            "compliance_check_enabled": true,
            "compliance_check_id": 1,
            "created_at": "2026-08-20T09:23:55.174524",
            "updated_at": "2026-08-20T09:23:55.175224"
        }
    ]
}
```

`job_id` is the primary key of the job the script anchors – it is what a recurring or one-time job schedules. `version` and `job_id` are read-only.

#### Add a script

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createScript"`

At least one of `arch_amd64` and `arch_arm64` must be true – a script that runs on no architecture never runs at all.

Example:

script.json

```json
{
  "name": "FileVault enabled",
  "description": "Check that FileVault is on",
  "source": "/usr/bin/fdesetup isactive",
  "tag": 1,
  "arch_amd64": true,
  "arch_arm64": true,
  "min_os_version": "14",
  "max_os_version": "",
  "compliance_check_enabled": true
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @script.json \
  https://$ZTL_FQDN/api/turbo/scripts/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "e6479cde-e17e-4f56-940e-7ccd59211c1a",
    "name": "FileVault enabled",
    "description": "Check that FileVault is on",
    "source": "/usr/bin/fdesetup isactive",
    "tag": 1,
    "arch_amd64": true,
    "arch_arm64": true,
    "min_os_version": "14",
    "max_os_version": "",
    "version": 1,
    "job_id": "70739ffd-b8f0-46ed-b8df-a0749a759779",
    "compliance_check_enabled": true,
    "compliance_check_id": 1,
    "created_at": "2026-08-20T09:23:55.174524",
    "updated_at": "2026-08-20T09:23:55.175224"
}
```

### /api/turbo/scripts/`<uuid:pk>`/

#### Get a script

* method: GET
* PBAC action: `Turbo::Action::"viewScript"`
* `<uuid:pk>`: the primary key of the script

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/scripts/e6479cde-e17e-4f56-940e-7ccd59211c1a/ \
  |python3 -m json.tool
```

#### Update a script

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateScript"`
* `<uuid:pk>`: the primary key of the script

Changing `source` bumps the version – the agents re-run the script. Changing any other attribute does not.

Example:

script.json

```json
{
  "name": "FileVault enabled",
  "description": "Check that FileVault is on",
  "source": "/usr/bin/fdesetup status | grep -q 'FileVault is On.'",
  "tag": 1,
  "arch_amd64": true,
  "arch_arm64": true,
  "min_os_version": "14",
  "max_os_version": "",
  "compliance_check_enabled": true
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @script.json \
  https://$ZTL_FQDN/api/turbo/scripts/e6479cde-e17e-4f56-940e-7ccd59211c1a/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "e6479cde-e17e-4f56-940e-7ccd59211c1a",
    "name": "FileVault enabled",
    "description": "Check that FileVault is on",
    "source": "/usr/bin/fdesetup status | grep -q 'FileVault is On.'",
    "tag": 1,
    "arch_amd64": true,
    "arch_arm64": true,
    "min_os_version": "14",
    "max_os_version": "",
    "version": 2,
    "job_id": "70739ffd-b8f0-46ed-b8df-a0749a759779",
    "compliance_check_enabled": true,
    "compliance_check_id": 1,
    "created_at": "2026-08-20T09:23:55.174524",
    "updated_at": "2026-08-20T09:23:55.183441"
}
```

Setting `compliance_check_enabled` to `false` deletes the compliance check and all its machine statuses.

#### Delete a script

* method: DELETE
* PBAC action: `Turbo::Action::"deleteScript"`
* `<uuid:pk>`: the primary key of the script

A script scheduled in a configuration cannot be deleted – delete its recurring and one-time jobs first.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/scripts/e6479cde-e17e-4f56-940e-7ccd59211c1a/
```

### /api/turbo/mscp_checks/

Terraform resource: [`zentral_turbo_mscp_check`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_mscp_check)

#### List all mSCP checks

* method: GET
* PBAC action: `Turbo::Action::"viewMSCPCheck"`
* Optional filter parameters:
    * `rule_id`: the mSCP rule identifier
    * `baseline`: the mSCP baseline key
    * `configuration`: primary key of a Turbo configuration – the checks scheduled in it, as a recurring or a one-time job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://$ZTL_FQDN/api/turbo/mscp_checks/?baseline=cis_lvl1" \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "a657104d-952b-489c-9816-14a32f12c7b6",
            "rule_id": "os_gatekeeper_enable",
            "baseline": "cis_lvl1",
            "odv_int": null,
            "odv_string": null,
            "odv_bool": null,
            "version": 1,
            "job_id": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
            "compliance_check_id": 2,
            "created_at": "2026-08-20T09:23:55.186614",
            "updated_at": "2026-08-20T09:23:55.186616"
        }
    ]
}
```

#### Add an mSCP check

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createMSCPCheck"`

`rule_id` is required. At most one of `odv_int`, `odv_string` and `odv_bool` may be set, and an ODV cannot be combined with a `baseline`.

Example – track a baseline's default ODV:

mscp_check.json

```json
{
  "rule_id": "os_gatekeeper_enable",
  "baseline": "cis_lvl1"
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @mscp_check.json \
  https://$ZTL_FQDN/api/turbo/mscp_checks/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "a657104d-952b-489c-9816-14a32f12c7b6",
    "rule_id": "os_gatekeeper_enable",
    "baseline": "cis_lvl1",
    "odv_int": null,
    "odv_string": null,
    "odv_bool": null,
    "version": 1,
    "job_id": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
    "compliance_check_id": 2,
    "created_at": "2026-08-20T09:23:55.186614",
    "updated_at": "2026-08-20T09:23:55.186616"
}
```

Example – pin an ODV:

mscp_check.json

```json
{
  "rule_id": "pwpolicy_minimum_length_enforce",
  "odv_int": 12
}
```

Response:

```json
{
    "id": "ef3bf5b6-66da-444d-b0a3-75b9a459f518",
    "rule_id": "pwpolicy_minimum_length_enforce",
    "baseline": "",
    "odv_int": 12,
    "odv_string": null,
    "odv_bool": null,
    "version": 1,
    "job_id": "c59376a9-4c10-4f6b-9397-ba12ca312d29",
    "compliance_check_id": 3,
    "created_at": "2026-08-20T09:23:55.189108",
    "updated_at": "2026-08-20T09:23:55.189110"
}
```

### /api/turbo/mscp_checks/`<uuid:pk>`/

#### Get an mSCP check

* method: GET
* PBAC action: `Turbo::Action::"viewMSCPCheck"`
* `<uuid:pk>`: the primary key of the mSCP check

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/mscp_checks/a657104d-952b-489c-9816-14a32f12c7b6/ \
  |python3 -m json.tool
```

#### Update an mSCP check

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateMSCPCheck"`
* `<uuid:pk>`: the primary key of the mSCP check

Every attribute is identity-bearing, so any change bumps the version and renames the compliance check.

Example:

mscp_check.json

```json
{
  "rule_id": "os_gatekeeper_enable",
  "baseline": "stig"
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @mscp_check.json \
  https://$ZTL_FQDN/api/turbo/mscp_checks/a657104d-952b-489c-9816-14a32f12c7b6/ \
  |python3 -m json.tool
```

#### Delete an mSCP check

* method: DELETE
* PBAC action: `Turbo::Action::"deleteMSCPCheck"`
* `<uuid:pk>`: the primary key of the mSCP check

An mSCP check scheduled in a configuration cannot be deleted. Deleting one also deletes its compliance check and all its machine statuses.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/mscp_checks/a657104d-952b-489c-9816-14a32f12c7b6/
```

### /api/turbo/recurring_jobs/

Terraform resource: [`zentral_turbo_recurring_job`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_recurring_job)

#### List all recurring jobs

* method: GET
* PBAC action: `Turbo::Action::"viewRecurringJob"`
* Optional filter parameters:
    * `configuration`: primary key of the Turbo configuration
    * `job`: primary key of the job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/ \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "a4193fe0-4011-4926-8f54-b83d3e9d6987",
            "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
            "job": "70739ffd-b8f0-46ed-b8df-a0749a759779",
            "interval": 3600,
            "tags": [
                1
            ],
            "excluded_tags": [
                2
            ],
            "serial_numbers": [
                "012345678"
            ],
            "excluded_serial_numbers": [
                "987654321"
            ],
            "created_at": "2026-08-20T09:23:55.196577",
            "updated_at": "2026-08-20T09:23:55.196579"
        }
    ]
}
```

#### Add a recurring job

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createRecurringJob"`

`job` is the `job_id` of a script or an mSCP check. A job can be scheduled at most once per configuration.

Example:

recurring_job.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "job": "70739ffd-b8f0-46ed-b8df-a0749a759779",
  "interval": 3600,
  "tags": [1],
  "excluded_tags": [2],
  "serial_numbers": ["012345678"],
  "excluded_serial_numbers": ["987654321"]
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @recurring_job.json \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "a4193fe0-4011-4926-8f54-b83d3e9d6987",
    "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "job": "70739ffd-b8f0-46ed-b8df-a0749a759779",
    "interval": 3600,
    "tags": [
        1
    ],
    "excluded_tags": [
        2
    ],
    "serial_numbers": [
        "012345678"
    ],
    "excluded_serial_numbers": [
        "987654321"
    ],
    "created_at": "2026-08-20T09:23:55.196577",
    "updated_at": "2026-08-20T09:23:55.196579"
}
```

Leave `interval` out, or set it to `null`, to use the configuration's `default_check_interval`.

### /api/turbo/recurring_jobs/`<uuid:pk>`/

#### Get a recurring job

* method: GET
* PBAC action: `Turbo::Action::"viewRecurringJob"`
* `<uuid:pk>`: the primary key of the recurring job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/a4193fe0-4011-4926-8f54-b83d3e9d6987/ \
  |python3 -m json.tool
```

#### Update a recurring job

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateRecurringJob"`
* `<uuid:pk>`: the primary key of the recurring job

`configuration` and `job` cannot be changed – send their current values. The interval and the scope can be updated.

Example:

recurring_job.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "job": "70739ffd-b8f0-46ed-b8df-a0749a759779",
  "interval": 7200,
  "tags": [1],
  "excluded_tags": [],
  "serial_numbers": [],
  "excluded_serial_numbers": []
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @recurring_job.json \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/a4193fe0-4011-4926-8f54-b83d3e9d6987/ \
  |python3 -m json.tool
```

#### Delete a recurring job

* method: DELETE
* PBAC action: `Turbo::Action::"deleteRecurringJob"`
* `<uuid:pk>`: the primary key of the recurring job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/a4193fe0-4011-4926-8f54-b83d3e9d6987/
```

### /api/turbo/one_time_jobs/

Terraform resource: [`zentral_turbo_one_time_job`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/turbo_one_time_job)

#### List all one-time jobs

* method: GET
* PBAC action: `Turbo::Action::"viewOneTimeJob"`
* Optional filter parameters:
    * `configuration`: primary key of the Turbo configuration
    * `job`: primary key of the job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/ \
  |python3 -m json.tool
```

Response:

```json
{
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "id": "94c61ba9-abc9-4aaf-99f3-b9ea2552d62a",
            "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
            "job": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
            "not_before": "2026-09-01T00:00:00",
            "not_after": "2026-09-30T00:00:00",
            "tags": [],
            "excluded_tags": [],
            "serial_numbers": [
                "012345678"
            ],
            "excluded_serial_numbers": [],
            "created_at": "2026-08-20T09:23:55.207650",
            "updated_at": "2026-08-20T09:23:55.207652"
        }
    ]
}
```

#### Add a one-time job

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createOneTimeJob"`

`job` is the `job_id` of a script or an mSCP check. `not_before` and `not_after` are both optional; when both are set, `not_after` must be on or after `not_before`.

Example:

one_time_job.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "job": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
  "not_before": "2026-09-01T00:00:00Z",
  "not_after": "2026-09-30T00:00:00Z",
  "serial_numbers": ["012345678"]
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @one_time_job.json \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/ \
  |python3 -m json.tool
```

Response:

```json
{
    "id": "94c61ba9-abc9-4aaf-99f3-b9ea2552d62a",
    "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
    "job": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
    "not_before": "2026-09-01T00:00:00",
    "not_after": "2026-09-30T00:00:00",
    "tags": [],
    "excluded_tags": [],
    "serial_numbers": [
        "012345678"
    ],
    "excluded_serial_numbers": [],
    "created_at": "2026-08-20T09:23:55.207650",
    "updated_at": "2026-08-20T09:23:55.207652"
}
```

### /api/turbo/one_time_jobs/`<uuid:pk>`/

#### Get a one-time job

* method: GET
* PBAC action: `Turbo::Action::"viewOneTimeJob"`
* `<uuid:pk>`: the primary key of the one-time job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/94c61ba9-abc9-4aaf-99f3-b9ea2552d62a/ \
  |python3 -m json.tool
```

#### Update a one-time job

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateOneTimeJob"`
* `<uuid:pk>`: the primary key of the one-time job

`configuration` and `job` cannot be changed – send their current values. The delivery window and the scope can be updated.

Example:

one_time_job.json

```json
{
  "configuration": "194a8af8-9e57-41b2-9b17-66ebc568c2dc",
  "job": "442d69d1-922e-4286-b7b7-3bc1c107a87c",
  "not_before": null,
  "not_after": "2026-10-31T00:00:00Z",
  "serial_numbers": ["012345678"]
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT -d @one_time_job.json \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/94c61ba9-abc9-4aaf-99f3-b9ea2552d62a/ \
  |python3 -m json.tool
```

#### Delete a one-time job

* method: DELETE
* PBAC action: `Turbo::Action::"deleteOneTimeJob"`
* `<uuid:pk>`: the primary key of the one-time job

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/94c61ba9-abc9-4aaf-99f3-b9ea2552d62a/
```

## Device API

These are the endpoints the agent uses. They are documented for reference and for troubleshooting – they are not meant to be called by anything else.

### /public/turbo/enroll/

Exchange an enrollment secret for a per-device token.

* method: POST
* Content-Type: application/json
* authentication: none

Request:

```json
{
  "secret": "kDnyGL3w6nw2xUyD1VnS8g708hEFZz5WbGTv2bLCvKCbeeXerIMVYCtNgiXz5U2D",
  "serial_number": "012345678",
  "hardware_uuid": "8CBB0A2C-1B4B-4A9F-9F0E-1D8B2F3A4C5D"
}
```

Response:

```json
{
    "token": "vPDj5oex41X7KTCeBIwSR5NBrImofPFAb8dbZhz5pLWCf1HhyQxCTpUeD7s3n7lf"
}
```

A rejected enrollment always answers `400` with `{"error": "invalid_enrollment"}`, whether the body was malformed or the secret was refused – and whichever restriction refused it. An unauthenticated caller must not learn which.

### /public/turbo/enrollment/

Get the enrollment's current version. The agent polls it to notice a version bump.

* method: GET
* authentication: `Authorization: ZtlEnrollmentSecret <secret>`

Response:

```json
{
    "pk": 3,
    "version": 1
}
```

### /public/turbo/config/

Get the machine's operating parameters and the jobs currently in scope for it.

* method: GET
* authentication: `Authorization: TurboEnrolledMachine <token>`

Response:

```json
{
    "config_refresh_interval": 600,
    "results_batch_size": 100,
    "collect_inventory": true,
    "inventory_interval": 86400,
    "jobs": [
        {
            "kind": "script",
            "pk": "d6bb179f-5530-4f05-a55d-6416d9660a0b",
            "version": 1,
            "schedule": {
                "mode": "recurring",
                "pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f",
                "interval": 3600
            },
            "payload": {
                "source": "/usr/bin/fdesetup isactive",
                "compliance": true,
                "arch_amd64": true,
                "arch_arm64": true,
                "min_os_version": "14",
                "max_os_version": ""
            }
        },
        {
            "kind": "mscp_check",
            "pk": "793615de-0d59-41c1-aa57-524c44a8153b",
            "version": 1,
            "schedule": {
                "mode": "one_time",
                "pk": "af1a90a9-9afd-417b-ac24-808e0a42d62f"
            },
            "payload": {
                "rule_id": "os_gatekeeper_enable",
                "baseline": "cis_lvl1"
            }
        }
    ]
}
```

Each entry in `jobs` carries:

|Attribute|Description|
|---|---|
|`kind`|`script`, `mscp_check`, or a command kind (`sysdiagnose`, `file_export`).|
|`pk`|The primary key of the job – the identity of the definition.|
|`version`|The current version of the definition.|
|`schedule.mode`|`recurring` or `one_time`.|
|`schedule.pk`|The primary key of the schedule. This is the handle the agent reports results and status against.|
|`schedule.interval`|Recurring jobs only – the effective interval, the schedule's own or the configuration's default.|
|`payload`|The definition, as the agent needs it: the source and the compatibility gate for a script, the rule and its ODV for an mSCP check.|

A recurring job is served for as long as it is in scope. A one-time job is served while it is inside its delivery window and until a result for the current version comes back.

### /public/turbo/results/

Upload the results of the runs the agent has accumulated.

* method: POST
* Content-Type: application/json
* authentication: `Authorization: TurboEnrolledMachine <token>`

Request:

```json
{
    "results": [
        {
            "kind": "script",
            "pk": "d6bb179f-5530-4f05-a55d-6416d9660a0b",
            "version": 1,
            "run": {
                "at": "2026-08-20T09:14:03Z",
                "duration": 0.412,
                "schedule_pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f",
                "mode": "recurring"
            },
            "result": {
                "exit_code": 0
            }
        },
        {
            "kind": "mscp_check",
            "pk": "793615de-0d59-41c1-aa57-524c44a8153b",
            "version": 1,
            "run": {
                "at": "2026-08-20T09:14:05Z",
                "duration": 1.238,
                "schedule_pk": "af1a90a9-9afd-417b-ac24-808e0a42d62f",
                "mode": "one_time"
            },
            "result": {
                "status": 300
            }
        }
    ]
}
```

|Attribute|Description|
|---|---|
|`run.schedule_pk`|**Required.** The schedule the run belongs to. This is what correlates the result.|
|`run.at`|**Required.** When the job ran on the device. It becomes the event's `created_at`.|
|`run.duration`|Optional. How long the run took, in seconds.|
|`run.mode`|Optional, informational – the correlation is on `schedule_pk` alone.|
|`kind`|The job kind. Optional, but expected: when present it must agree with the resolved schedule, or the entry is skipped. A kind this Zentral does not know is *not* rejected – during a rolling upgrade the instances do not share a set of kinds, and a report of a run that happened must not be dropped. It is skipped with `unknown_job_kind`, and the schedule still records the run.|
|`pk`, `version`|Declarative. The resolved schedule stays authoritative.|
|`result.exit_code`|Scripts – the process exit code, or `null` when the script could not run.|
|`result.status`|mSCP checks – the compliance status code. See [Compliance checks](#compliance-checks).|

Response:

```json
{
    "accepted": [
        {
            "schedule_pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f",
            "at": "2026-08-20T09:14:03+00:00"
        },
        {
            "schedule_pk": "af1a90a9-9afd-417b-ac24-808e0a42d62f",
            "at": "2026-08-20T09:14:05+00:00"
        }
    ],
    "skipped": []
}
```

Each entry is acknowledged by its `(schedule_pk, at)` identity. A skipped entry carries the reason:

```json
{
    "accepted": [],
    "skipped": [
        {
            "schedule_pk": "6f2b9f6e-0000-0000-0000-000000000000",
            "at": "2026-08-20T09:14:03+00:00",
            "reason": "unknown_schedule"
        },
        {
            "schedule_pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f",
            "at": "2026-08-20T09:14:04+00:00",
            "reason": "kind_mismatch"
        }
    ]
}
```

See [Tolerant batches](#tolerant-batches) for the entries that appear in neither list.

### /public/turbo/status/

Report the jobs the agent currently holds.

* method: POST
* Content-Type: application/json
* authentication: `Authorization: TurboEnrolledMachine <token>`

Request:

```json
{
    "jobs": [
        {
            "kind": "script",
            "pk": "d6bb179f-5530-4f05-a55d-6416d9660a0b",
            "version": 1,
            "schedule": {
                "mode": "recurring",
                "pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f",
                "interval": 3600
            },
            "last_run": {
                "at": "2026-08-20T09:14:03Z",
                "exit_code": 0
            }
        },
        {
            "kind": "mscp_check",
            "pk": "793615de-0d59-41c1-aa57-524c44a8153b",
            "version": 1,
            "schedule": {
                "mode": "one_time",
                "pk": "af1a90a9-9afd-417b-ac24-808e0a42d62f"
            },
            "last_run": null
        }
    ]
}
```

`schedule.pk` is required; `version`, `schedule.mode` and `schedule.interval` are the plan the agent holds, echoed back. `last_run` is an open object, reported for the event only.

The report is the agent's **full** held set: the per-machine rows it does not mention are marked as removed.

Response:

```json
{
    "accepted": [
        {
            "schedule_pk": "eedc8b1c-03c4-41a4-bae9-0af222b7926f"
        },
        {
            "schedule_pk": "af1a90a9-9afd-417b-ac24-808e0a42d62f"
        }
    ],
    "skipped": []
}
```

### /public/turbo/inventory/

Post a full machine inventory snapshot.

* method: POST
* Content-Type: application/json
* authentication: `Authorization: TurboEnrolledMachine <token>`

The body is an inventory snapshot tree – its contents are the [inventory](inventory.md) pipeline's contract, not Turbo's. Zentral sets the source, the serial number and the public IP address itself, and adds the enrollment's business unit.

Response:

```json
{}
```
