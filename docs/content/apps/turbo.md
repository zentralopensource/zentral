---
title: Turbo
weight: 250
---

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

A **job** is what Turbo runs on a machine. There are four kinds:

 * a **script** – a zsh script, whose exit code is the outcome,
 * an **mSCP check** – an mSCP rule, whose check logic and baseline defaults are bundled in the agent,
 * a **sysdiagnose** – a `sysdiagnose` archive of the machine, uploaded to Zentral,
 * a **file export** – the files that match a list of path patterns, uploaded to Zentral.

Creating a script, an mSCP check, a sysdiagnose or a file export only *defines* the job. It does not run anywhere until it is scheduled in a configuration, as a [recurring job](#recurring-jobs) or a [one-time job](#one-time-jobs). The same definition can be scheduled in several configurations.

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

### Sysdiagnoses

A sysdiagnose collects a `sysdiagnose` archive from a machine and uploads it. It has no options: the agent runs the tool unattended and uploads the archive that the tool produces.

Create a sysdiagnose with the [API](#apiturbosysdiagnoses). The web console does not create sysdiagnoses yet. *Turbo > Sysdiagnoses* lists them.

|Attribute|Description|
|---|---|
|`name`|A name. Two sysdiagnoses cannot have the same name.|
|`description`|Optional.|

See [Collected files](#collected-files) for the rules that apply to a sysdiagnose and to a file export.

### File exports

A file export collects the files that match a list of path patterns. It uploads them with a manifest of what it collected.

Create a file export with the [API](#apiturbofile_exports). The web console does not create file exports yet. *Turbo > File exports* lists them and shows their patterns.

|Attribute|Description|
|---|---|
|`name`|A name. Two file exports cannot have the same name.|
|`description`|Optional.|
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

A file export run produces two files: a manifest, which lists what was matched, collected, skipped and unreadable, and an archive of the collected files. The manifest is a separate file so an operator can read what a run collected without downloading the archive. A run that matched nothing uploads the manifest and no archive.

See [Collected files](#collected-files) for the rules that apply to a sysdiagnose and to a file export.

### Collected files

A sysdiagnose and a file export collect files from a machine. Unlike a script or an mSCP check, they have no compliance role and produce no verdict.

**A sysdiagnose and a file export run one time only.** They cannot be attached to a recurring job, because a repeated collection is not a job. Schedule them with a one-time job, or with the *Schedule one-time job* action on a machine page.

A change to the options of a file export bumps its [version](#job-versions). A machine that has not reported a result yet gets the new options. A machine that has reported does not run it again: create a new one-time job. A new name or a new description does not bump the version.

A sysdiagnose or a file export cannot be deleted while it is scheduled in a configuration.

Collecting a `sysdiagnose` archive, and even more so collecting arbitrary files, reads user data. Use a [policy](../configuration/pbac.md) to say which kinds a role may schedule. See [Scheduling permissions](#scheduling-permissions).

### Scheduling permissions

Six actions authorize the scheduling of a job:

|Action|Resource|
|---|---|
|`Turbo::Action::"createOneTimeJob"`|The **configuration**. The schedule does not exist yet, so the resource is the configuration it will be created in.|
|`Turbo::Action::"updateOneTimeJob"`|The **schedule**.|
|`Turbo::Action::"deleteOneTimeJob"`|The **schedule**.|
|`Turbo::Action::"createRecurringJob"`|The **configuration**, as for a one-time job.|
|`Turbo::Action::"updateRecurringJob"`|The **schedule**.|
|`Turbo::Action::"deleteRecurringJob"`|The **schedule**.|

A schedule is a member of its configuration, so a policy scoped to a configuration covers the six actions. All six carry the job in `context.job`, so one policy can name them all. Refuse a kind with a `forbid`:

```
forbid (
  principal,
  action in [Turbo::Action::"createOneTimeJob",
             Turbo::Action::"updateOneTimeJob",
             Turbo::Action::"deleteOneTimeJob"],
  resource
) when { context.job.kind == "file_export" };
```

The kinds are `script`, `mscp_check`, `sysdiagnose` and `file_export`. Every kind is covered, so the same policy shape restricts a script. A file export runs one time only, so this policy names the one-time actions only. A script and an mSCP check can also run on a recurring job. To refuse one of them, add `createRecurringJob`, `updateRecurringJob` and `deleteRecurringJob` to the list.

A grant can name the kind directly, and needs no companion `forbid`:

```
permit (
  principal in Role::"<role id>",
  action == Turbo::Action::"createOneTimeJob",
  resource
) when { context.job.kind == "sysdiagnose" };
```

That role can schedule a `sysdiagnose` and nothing else. It still opens the *Schedule one-time job* page, which the view permission gates, and the picker there offers the kinds that the policy permits. The submit is what applies the policy. Zentral hides the action, and refuses the page, only when **no** kind could be permitted.

Because the resource is the configuration or one of its schedules, one grant can give the scheduling in one configuration:

```
permit (
  principal in Role::"<role id>",
  action in [Turbo::Action::"createOneTimeJob",
             Turbo::Action::"updateOneTimeJob",
             Turbo::Action::"deleteOneTimeJob",
             Turbo::Action::"createRecurringJob",
             Turbo::Action::"updateRecurringJob",
             Turbo::Action::"deleteRecurringJob"],
  resource in Turbo::Configuration::"<configuration id>"
);
```

`updateOneTimeJob` is included in the refusal above because the job of a schedule cannot be changed, but its tags, its serial numbers and its window can. Widening the reach of a `file_export` schedule is a scheduling act.

`deleteOneTimeJob` is in the list because removing a schedule stops it being served to the machines that have not run it yet. A policy that governs a kind governs its removal too.

An update or delete policy can also read the schedule itself, which a create policy cannot — there is no schedule yet when one is created:

```
forbid (
  principal,
  action == Turbo::Action::"updateOneTimeJob",
  resource
) when { resource.job.kind == "file_export" };
```

Use `context.job` when one policy should cover several actions, and `resource` when a policy needs the schedule — to name one, or to read more of it than the job.

The machines are not the resource. A schedule targets tags and serial numbers, and tag membership changes after the schedule is written, so there is no machine for a policy to name.

The scheduling pages also need a view permission, because a create action needs the job to decide and the form has not picked one yet. Under a configuration, the one-time job page needs `turbo.view_onetimejob`, and the recurring job page needs `turbo.view_recurringjob`. The machine page needs `turbo.view_enrolledmachine`: Zentral knows the configuration only after it resolves the serial number, so the scheduling action cannot be the first gate, and the response must not tell the user if a serial number is enrolled.

The `add`, `change` and `delete` permissions of the one-time jobs and of the recurring jobs do not authorize anything. A role schedules a job with these six actions only.

Seeing the schedules is a permission, `turbo.view_onetimejob` or `turbo.view_recurringjob`, not a typed action: scoping a list means filtering it by policy rather than deciding one request, which is a separate piece of work.

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
|`job`|The script, mSCP check, sysdiagnose or file export to run.|
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

A definition carries a version, which Zentral bumps when the definition changes: for a script, when its `source` changes; for an mSCP check, when any of its attributes changes – they are all identity-bearing; for a file export, when its options change. A sysdiagnose has no options, so its version does not change.

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

### Uploads

Some jobs produce a file: a sysdiagnose archive, or a set of exported files. The file does not travel in the result. The agent asks Zentral for a destination, sends the file there, and reports what it did in the result.

The agent asks for a destination just in time, once for each artifact of each run. Upload URLs are never in the config payload. That payload is a pure function of the definition and its version, it is cached, and it is served again to every machine in scope. A URL in it would be expired for the machines that need it, and a live write credential for the machines that do not. See [`/public/turbo/uploads/`](#publicturbouploads).

Zentral builds the object key, and the key is stable for the life of the upload. A retry signs the same key again and replaces the object, so a failed attempt never leaves a partial twin behind. The file name is built at the first request, from the artifact declaration, the serial number and the time.

Where the bytes go depends on the storage backend:

 * When the default storage can sign a `PUT` – S3 – the agent sends the file directly to the bucket. Zentral reads none of it, and the size and the digest are signed into the destination, so the storage itself refuses a body that does not match.
 * When the storage cannot sign a `PUT`, Zentral hosts the destination and the bytes go through the web workers. Only S3 can sign a `PUT` today, so this is the path a Google Cloud Storage deployment takes, and it cannot choose otherwise. Use it in development, or for a small on-premises installation. The size limit is then the body limit of the deployment itself, `DATA_UPLOAD_MAX_MEMORY_SIZE`, which is 10 MiB by default. Raise it only together with the `client_max_body_size` of your reverse proxy: the smaller of the two is what the agent meets, and the published limit only knows about the first.

The agent sees the same `mode: "put"` shape in both cases, and does not know which storage is behind it.

#### Multipart

With an S3 storage backend, a large artifact goes up in parts. Zentral decides this, not the agent. The response to the request for a destination has `mode: "multipart"`, the part size, and one signed URL for each part. The agent sends the same request in the two modes, and reads the mode in the response.

The parts make a resume possible. A 400 MiB `PUT` that fails at 95 % starts again from zero, but a failed part is sent again alone. When the part URLs expire, the agent sends the same request again, with the numbers of the missing parts. Zentral signs only these parts, with the part size of the upload.

A resume does not send the key or the `upload_id`. The run and the artifact identify the upload, and the upload always keeps the same multipart upload at the storage. The list of missing parts tells Zentral that the other parts are in the storage. So Zentral accepts the list only for a multipart upload that has started, and does not create an upload for it: an object with only some of its parts cannot be assembled. The agent keeps the run id with its record of the parts that it sent. A request without the list starts again: Zentral signs all the parts, and the agent sends all the parts.

The limit is two parts of 64 MiB, so 128 MiB. With a limit of one part size, an artifact of one more byte has a second part of one byte, and a failed first part costs as much as a failed single `PUT`. With two part sizes, a resume saves at least one full part.

**Zentral completes the upload, not the agent.** When all the parts are sent, the agent sends the `run` block and the artifact name to [`/public/turbo/uploads/complete/`](#publicturbouploadscomplete), and gets a `202`. Zentral gets the list of parts from the storage, never from a request, and completes the upload with its own credentials. So the agent needs no knowledge of the storage: a completion needs the entity tags of the parts and a request body, and S3 can send an error inside a `200` response.

The completion runs in the background, because S3 documents that it can take some minutes. The verification of the upload records its result. The call is idempotent, so the agent can send it again. When a result arrives for an upload that is not complete, Zentral asks for the completion again. The completion makes no retries. After a storage outage, the upload stays `pending`, and the `sweep_turbo_uploads` [maintenance](#maintenance) command asks again.

The completion verifies a multipart upload. The agent declares the CRC-64/NVME of the full file when it asks for the destination. Zentral gives this value at the completion, and the storage refuses a file with another CRC. That failure is `assembly_failed`. So the config asks for this digest, and Zentral refuses a multipart artifact without it: the SHA-256 cannot do this on a multipart upload. Zentral also compares the result with the request for the destination: a result with another `size` or `sha256` is a `mismatch`. A decided verification is final. The completion writes only over `pending`, and Zentral answers `already_uploaded` to a request for a destination after the decision.

When the result reports that a multipart upload failed, Zentral deletes the parts. Zentral also deletes them when a result does not agree with the request for the destination before the completion: the verification is then `mismatch`, and no completion follows. A result can arrive late, or never, so the bucket also needs a rule that deletes the parts. The storage keeps the parts until something deletes them, and you pay for them. See [Bucket rules](#bucket-rules).

#### Bucket rules

Zentral writes the artifacts, but it does not delete them. If you manage your own deployment, set these S3 lifecycle rules on the bucket:

|Rule|Scope|Reason|
|---|---|---|
|`Expiration`|`turbo/uploads/`|Only this rule deletes a collected artifact. An artifact has the data of the person who uses the machine, so keep it only for the time that you need it. 14 days is a good default.|
|`AbortIncompleteMultipartUpload`|The bucket|Only this rule deletes the parts of a [multipart](#multipart) upload that the agent never reports. An `Expiration` rule does not delete them, because their object does not exist. 7 days gives time to an agent that sends a large artifact again over some cycles.|

If the storage has a `location`, the keys start with it, and the prefix of the `Expiration` rule is `<location>/turbo/uploads/`. A rule on `turbo/uploads/` then deletes nothing, and nothing tells you.

Set the abort rule on the bucket, not only on `turbo/uploads/`. All the clients can start a multipart upload, for example the AWS SDK for a large file, and a stopped upload keeps its parts. The rule deletes only the parts of an incomplete upload, never a complete object.

If the bucket has versioning, add a rule with `ExpiredObjectDeleteMarker`. An expiration adds a delete marker, and the object version becomes noncurrent. A noncurrent version rule deletes the version, but not the marker. Put `ExpiredObjectDeleteMarker` in a rule of its own: one `Expiration` cannot have `ExpiredObjectDeleteMarker` and a number of days.

After a rule deletes an artifact, its download gives a `404`: Zentral reads the metadata of the file before the download. The row stays on the machine page, because it records that the job collected an artifact.

[Config](#configuration) publishes `upload_max_size` and `upload_digests`. The agent can then refuse a file that is too large before it collects it, and compute the digests the storage wants in the same pass as the SHA-256.

The result closes the upload. It carries a `run.id`, and one entry in `result.uploads` for each declared artifact. The entry reports the upload, or the reason it failed. Zentral compares the key the agent echoes with the key it minted, and refuses an echo that does not match: the key never comes from the wire.

Partial success is a normal outcome. A `file_export` that sends its manifest and fails on its archive keeps the manifest: the two artifacts are two rows, and they close one at a time.

The agent's report is the first axis, and Zentral records it immediately. Whether the storage agrees is a second axis.

#### Verification

When the agent reports an upload, Zentral compares the size and the SHA-256 of the stored object with the ones the agent declared when it asked for the destination.

Those two numbers reach the comparison by two independent paths. They went out at the request for a destination and were signed into the upload, so the storage refused any body that did not match them, and they come back as the checksum the storage recorded. They also come home a second time in the result. Verification is where the two copies meet, and on a storage that signs, Zentral reads no part of the file to do it. Google Cloud Storage takes the hosted destination, which compares the body with the declared SHA-256 before it stores it. Google Cloud Storage also records a CRC32C of every object, so Zentral compares that value with the CRC32C the agent declared, and reads no part of the file there either. Only the file system storage records no digest: Zentral then reads the object and hashes it, which is a local read under the low size limit.

Zentral checks both paths. A result that echoes a size or a digest which is not the one it asked for is a `mismatch`, whatever is at the key: an agent that requests a destination for one file and reports another has described two files, and only one of them was stored. Echoing them at all is optional — the request for the destination is what was signed either way.

The outcome is a separate field on the upload, next to the status:

|Verification|Meaning|
|---|---|
|`pending`|Not decided yet.|
|`verified`|The stored object is the size and the digest the agent declared: the SHA-256, the CRC32C on Google Cloud Storage, or the CRC-64/NVME of a [multipart](#multipart) upload.|
|`mismatch`|Something is at the key and it is not what the agent declared, or the result contradicts the request for the destination.|
|`missing`|There is nothing at the key.|
|`assembly_failed`|The storage could not assemble a [multipart](#multipart) upload. The parts do not make the file that the agent declared.|

The outcome rides the result event as well, as `verification` on the `result.uploads` entry. It is the outcome itself and not a yes or no, because `mismatch` and `missing` are different problems and a consumer of the event cannot go to the database to tell them apart.

Some answers are not answers, and Zentral records none of them. A storage that times out, a key the deployment cannot read, an object with no stored digest, or an upload to Google Cloud Storage with no declared CRC32C all leave the verification `pending`, with a log entry, and put no `verification` on the event. Recording a transient failure as `missing` would be worse than recording nothing: the object is very likely there, and the row would say for ever that it is not.

Give Zentral `s3:ListBucket` on the bucket. Without it S3 answers 403 rather than 404 for a key that does not exist, and Zentral cannot tell a missing object from one it may not read: the upload stays `pending`, and every result for it writes an error to the log.

#### See and download an artifact

The page of an enrolled machine lists the artifacts that its jobs collected. Each row gives the size and the state of the artifact, and a download link when the upload is complete.

Two PBAC actions control this list:

|Action|Group|Permits|
|---|---|---|
|`Turbo::Action::"viewJobUpload"`|Admin, User, **Viewer**|See that a job collected an artifact, and the state of the upload.|
|`Turbo::Action::"downloadJobUpload"`|Admin, User|Download the artifact.|

To see that a sysdiagnose exists is a view. A download gives the data of the person who uses the machine, so the Viewer group does not have `downloadJobUpload`. An artifact that a user cannot see is not on the page, so its name and its size stay hidden.

Each download posts a `turbo_artifact_downloaded` [event](#events).

The resource of the two actions is the upload. It is a member of two containers:

* `Inventory::Machine`, the machine that the data comes from. The parents of the machine give the meta business unit scope.
* `Turbo::OneTimeJob` or `Turbo::RecurringJob`, the schedule that collected the artifact. The schedule is a member of its `Turbo::Configuration`.

So one policy covers the scheduling and the artifacts:

```
forbid (
  principal,
  action in [Turbo::Action::"createOneTimeJob", Turbo::Action::"updateOneTimeJob",
             Turbo::Action::"deleteOneTimeJob", Turbo::Action::"viewJobUpload",
             Turbo::Action::"downloadJobUpload"],
  resource in Turbo::Configuration::"a4d3e2b1-…"
);
```

Without the schedule container, this policy covers the scheduling, but not the artifacts. The two containers can also disagree: a configuration of one team can collect from a machine in the meta business unit of another team. A `forbid` on one of them applies. **The meta business unit scope alone is not a boundary.** A machine that enrolled, but has no inventory snapshot yet, is in no meta business unit for a policy.

The upload has the artifact name, and the job as an entity, so a policy can read the two:

```
forbid (
  principal,
  action == Turbo::Action::"downloadJobUpload",
  resource
) when { resource.job.kind == "file_export" };
```

The machine page also needs the `turbo.view_enrolledmachine` permission, which is global. A meta business unit scope for the machine pages is separate work. The [API](#apiturboone_time_jobsuuidpkmachines) uses the typed actions only.

**Verification never reopens a one-time job.** That is what the two axes are for: the job was done on that machine when the agent reported, whatever the storage says afterwards. A `mismatch` does not give the agent another destination, and it does not make Zentral ask for the file again.

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
|`turbo_artifact_downloaded`|`turbo`|A user or an API client downloaded an artifact that a job collected. The event has the serial number of the machine and the request. The payload has the `schedule` (`mode` and `pk`), the `artifact` name, and the `upload` (`pk`, `size` and `sha256`).|
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

The completion of a [multipart](#multipart) upload makes no retries. When the storage does not answer, the upload stays `pending`. A second management command asks again for these completions. Run it every hour:

```bash
python server/manage.py sweep_turbo_uploads
```

It asks again for an upload only when the result arrived 45 minutes ago or more, and the verification is `pending`. It asks for each upload one time in 45 minutes, at most. To change this value, use `--min-age`:

* Keep it longer than 30 minutes, the longest completion. If not, the command asks again for a completion that still runs.
* Keep it shorter than the interval of the cron, with a margin. If not, a run that starts a little early does not ask again for the uploads of the previous run.

The command does not ask for an upload without a result: the agent can still send parts.

You can run it on more than one server, at the same time or not. Each run claims its uploads in one transaction, and skips the uploads that another run has, or asked for in the window. So each upload gets one request, with any number of servers. A second request does no harm: the completion is idempotent, and a decided verification is final.

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

### /api/turbo/sysdiagnoses/

#### List all sysdiagnoses

* method: GET
* PBAC action: `Turbo::Action::"viewSysdiagnose"`
* Optional filter parameters:
    * `name`: name of the sysdiagnose
    * `configuration`: primary key of a Turbo configuration – the sysdiagnoses scheduled in it

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/sysdiagnoses/ \
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
            "id": "d1b9471f-5ccb-4c25-a5ff-19d831855303",
            "name": "Support archive",
            "description": "",
            "version": 1,
            "job_id": "5221c439-edc0-483a-affe-502c965d6336",
            "created_at": "2026-10-19T08:46:12.901263",
            "updated_at": "2026-10-19T08:46:12.901457"
        }
    ]
}
```

`job_id` is the primary key of the job of the sysdiagnose. A one-time job schedules it. `version` and `job_id` are read-only.

#### Add a sysdiagnose

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createSysdiagnose"`

A sysdiagnose has no options.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Support archive"}' \
  https://$ZTL_FQDN/api/turbo/sysdiagnoses/ \
  |python3 -m json.tool
```

### /api/turbo/sysdiagnoses/`<uuid:pk>`/

#### Get a sysdiagnose

* method: GET
* PBAC action: `Turbo::Action::"viewSysdiagnose"`
* `<uuid:pk>`: the primary key of the sysdiagnose

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/sysdiagnoses/d1b9471f-5ccb-4c25-a5ff-19d831855303/ \
  |python3 -m json.tool
```

#### Update a sysdiagnose

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateSysdiagnose"`
* `<uuid:pk>`: the primary key of the sysdiagnose

An update changes the name or the description. It does not change `version`.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT \
  -d '{"name": "Support archive", "description": "For the support team"}' \
  https://$ZTL_FQDN/api/turbo/sysdiagnoses/d1b9471f-5ccb-4c25-a5ff-19d831855303/ \
  |python3 -m json.tool
```

#### Delete a sysdiagnose

* method: DELETE
* PBAC action: `Turbo::Action::"deleteSysdiagnose"`
* `<uuid:pk>`: the primary key of the sysdiagnose

A sysdiagnose that is scheduled in a configuration cannot be deleted.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/sysdiagnoses/d1b9471f-5ccb-4c25-a5ff-19d831855303/
```

### /api/turbo/file_exports/

#### List all file exports

* method: GET
* PBAC action: `Turbo::Action::"viewFileExport"`
* Optional filter parameters:
    * `name`: name of the file export
    * `configuration`: primary key of a Turbo configuration – the file exports scheduled in it

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/file_exports/ \
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
            "id": "f3a2b979-5704-448b-ac14-ab4a1e043b6a",
            "name": "Install logs",
            "description": "The installer logs and Munki's",
            "patterns": [
                "/var/log/install.log*",
                "/Library/Logs/Munki/*.log"
            ],
            "max_size": 104857600,
            "version": 1,
            "job_id": "cc050216-5031-40cf-8cf0-d6b895bb1ffb",
            "created_at": "2026-10-19T08:46:12.895513",
            "updated_at": "2026-10-19T08:46:12.895814"
        }
    ]
}
```

`job_id` is the primary key of the job of the file export. A one-time job schedules it. `version` and `job_id` are read-only.

#### Add a file export

* method: POST
* Content-Type: application/json
* PBAC action: `Turbo::Action::"createFileExport"`

`patterns` is required. `max_size` is optional. See [File exports](#file-exports) for the rules.

Example:

file_export.json

```json
{
  "name": "Install logs",
  "description": "The installer logs and Munki's",
  "patterns": ["/var/log/install.log*", "/Library/Logs/Munki/*.log"]
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @file_export.json \
  https://$ZTL_FQDN/api/turbo/file_exports/ \
  |python3 -m json.tool
```

### /api/turbo/file_exports/`<uuid:pk>`/

#### Get a file export

* method: GET
* PBAC action: `Turbo::Action::"viewFileExport"`
* `<uuid:pk>`: the primary key of the file export

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/file_exports/f3a2b979-5704-448b-ac14-ab4a1e043b6a/ \
  |python3 -m json.tool
```

#### Update a file export

* method: PUT
* Content-Type: application/json
* PBAC action: `Turbo::Action::"updateFileExport"`
* `<uuid:pk>`: the primary key of the file export

An update replaces all the options. A `max_size` that is not in the request is the default value again.

A change to the options bumps `version`. A machine that has not reported a result yet gets the new options. A machine that has reported does not run the file export again: create a new one-time job. A change to the name or to the description only does not bump `version`.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X PUT \
  -d @file_export.json \
  https://$ZTL_FQDN/api/turbo/file_exports/f3a2b979-5704-448b-ac14-ab4a1e043b6a/ \
  |python3 -m json.tool
```

#### Delete a file export

* method: DELETE
* PBAC action: `Turbo::Action::"deleteFileExport"`
* `<uuid:pk>`: the primary key of the file export

A file export that is scheduled in a configuration cannot be deleted.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/turbo/file_exports/f3a2b979-5704-448b-ac14-ab4a1e043b6a/
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

`configuration` and `job` cannot be changed – send their current values. The interval and the scope can be updated. Send every attribute, with `null` or `[]` for an empty one: an attribute that is not in the body is a `400`.

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

### /api/turbo/recurring_jobs/`<uuid:pk>`/machines/

#### List the machines of a recurring job

The state of the job on each machine, as the machine page gives it.

* method: GET
* PBAC action: `Turbo::Action::"viewRecurringJobMachine"`, for each machine
* `<uuid:pk>`: the primary key of the recurring job
* Optional filter parameter:
    * `serial_number`: the serial number of a machine

The resource of the action is a member of the machine and of the recurring job, and the recurring job is a member of its configuration. So a policy can use the machine, its meta business units, the recurring job or its configuration. The resource also has the job, so a policy can read `resource.job.kind`. The list has only the machines that the caller can see. A caller without a policy gets an empty list, not a `403`.

A machine is in the list after the agent reports the job in its status. The attributes are the same as for a [one-time job](#apiturboone_time_jobsuuidpkmachines), with one more: `seen_interval`, the interval that the agent uses, in seconds. On a recurring job, `last_result_at` is the time of the last run, and Zentral continues to serve the job. A recurring job has no artifacts.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/recurring_jobs/3a1f1d3b-6f22-4a76-9a4a-b1d1a1f08b2a/machines/ \
  |python3 -m json.tool
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

`configuration` and `job` cannot be changed – send their current values. The delivery window and the scope can be updated. Send every attribute, with `null` or `[]` for an empty one: an attribute that is not in the body is a `400`.

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

### /api/turbo/one_time_jobs/`<uuid:pk>`/machines/

#### List the machines of a one-time job

The state of the job on each machine, with the artifacts that the job collected from it.

* method: GET
* PBAC action: `Turbo::Action::"viewOneTimeJobMachine"`, for each machine
* PBAC actions: `Turbo::Action::"viewJobUpload"` and `Turbo::Action::"downloadJobUpload"`, for each artifact
* `<uuid:pk>`: the primary key of the one-time job
* Optional filter parameter:
    * `serial_number`: the serial number of a machine

The resource of `viewOneTimeJobMachine` is a member of the machine and of the one-time job, and the one-time job is a member of its configuration. So a policy can use the machine, its meta business units, the one-time job or its configuration. The resource also has the job, so a policy can read `resource.job.kind`. The list has only the machines that the caller can see. A caller without a policy gets an empty list, not a `403`.

`artifacts` has only the artifacts that the caller can see. See [See and download an artifact](#see-and-download-an-artifact). `download_url` is `null` when the `status` is not `uploaded`, or when the caller cannot download the artifact.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/turbo/one_time_jobs/94c61ba9-abc9-4aaf-99f3-b9ea2552d62a/machines/ \
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
            "serial_number": "012345678",
            "seen_version": 1,
            "last_result_version": 1,
            "first_seen_at": "2026-08-20T09:10:02.511601",
            "last_seen_at": "2026-08-20T09:14:55.207650",
            "first_result_at": "2026-08-20T09:16:02.511601",
            "last_result_at": "2026-08-20T09:16:02.511601",
            "removed_at": null,
            "artifacts": [
                {
                    "id": "1f0f7a53-5a5e-4d6b-9a76-5b4f7e0b1c2d",
                    "run_id": "0f3b06d2-3f4e-4c2a-90c7-4d6c9dbb3d4c",
                    "artifact": "archive",
                    "mode": "put",
                    "size": 31457280,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "truncated": false,
                    "attempts": 1,
                    "status": "uploaded",
                    "error_reason": null,
                    "verification": "verified",
                    "created_at": "2026-08-20T09:15:41.207650",
                    "updated_at": "2026-08-20T09:16:02.511873",
                    "completed_at": "2026-08-20T09:16:02.511601",
                    "verified_at": "2026-08-20T09:16:02.511601",
                    "download_url": "https://zentral.example.com/api/turbo/artifacts/1f0f7a53-5a5e-4d6b-9a76-5b4f7e0b1c2d/download/"
                }
            ]
        }
    ]
}
```

|Attribute|Description|
|---|---|
|`seen_version`|The [version](#job-versions) of the job in the last status of the agent.|
|`first_seen_at`, `last_seen_at`|The first and the last status of the agent with the job.|
|`last_result_version`|The version of the latest run.|
|`first_result_at`, `last_result_at`|The first and the latest run of the current version. When `last_result_at` is set, the job is done on this machine, and Zentral does not serve it again.|
|`removed_at`|Set when the agent does not report the job anymore. `null` while the agent reports it.|
|`artifacts`|The artifacts of all the runs of the job on this machine. `run_id` tells the runs apart. `status` is what the agent reported, and `verification` is what the storage holds. See [Verification](#verification).|

A machine is in the list after the agent reports the job in its status. When `last_result_at` is set, the result closed the artifacts of the run.

### /api/turbo/artifacts/`<uuid:pk>`/download/

#### Download an artifact

* method: GET
* PBAC action: `Turbo::Action::"downloadJobUpload"`
* `<uuid:pk>`: the `id` of the artifact

Use the `download_url` of the artifact. With S3 or Google Cloud Storage, the response is a `302` to a signed URL of the storage. With the file system storage, the response has the file. Each download posts a `turbo_artifact_downloaded` [event](#events).

Zentral reads the metadata of the file before the response. The response is a `404` when the `status` is not `uploaded`, or when a bucket rule deleted the file. The response is a `503` when the storage does not give the metadata. For example, without `s3:ListBucket`, S3 answers a `403` for a file that does not exist.

Compare the SHA-256 of the file with the `sha256` of the artifact.

Example:

```bash
curl -L \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -o archive.tar.gz \
  https://$ZTL_FQDN/api/turbo/artifacts/1f0f7a53-5a5e-4d6b-9a76-5b4f7e0b1c2d/download/
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
    "upload_max_size": 2147483648,
    "upload_digests": ["crc64nvme"],
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
|`kind`|`script`, `mscp_check`, `sysdiagnose` or `file_export`.|
|`pk`|The primary key of the job – the identity of the definition.|
|`version`|The current version of the definition.|
|`schedule.mode`|`recurring` or `one_time`.|
|`schedule.pk`|The primary key of the schedule. This is the handle the agent reports results and status against.|
|`schedule.interval`|Recurring jobs only – the effective interval, the schedule's own or the configuration's default.|
|`payload`|The definition, as the agent needs it: the source and the compatibility gate for a script, the rule and its ODV for an mSCP check.|

A recurring job is served for as long as it is in scope. A one-time job is served while it is inside its delivery window and until a result for the current version comes back.

`upload_max_size` and `upload_digests` describe the [upload](#uploads) plane, and depend on the storage backend of the deployment. `upload_max_size` is the largest artifact the deployment accepts, in bytes; a job kind can be lower, and the server says so when the agent asks for a destination. `upload_digests` lists the digests to compute on top of the SHA-256, so the agent reads the file once. It is `["crc64nvme"]` with S3, `["crc32c"]` with Google Cloud Storage, and empty with the file system storage.

`upload_max_size` is 2 GiB with an S3 storage backend, and the `DATA_UPLOAD_MAX_MEMORY_SIZE` of the deployment without one. The endpoint that mints destinations refuses the same limit, so an artifact that is too large is refused before the agent sends a byte.

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
        },
        {
            "kind": "sysdiagnose",
            "pk": "1c0a5a30-1cf6-4a2f-8c1e-7d0c2d4c9a11",
            "version": 1,
            "run": {
                "at": "2026-08-20T09:15:41Z",
                "duration": 96.4,
                "schedule_pk": "b1d1a1f0-8b2a-4a76-9a4a-3a1f1d3b6f22",
                "id": "0f3b06d2-3f4e-4c2a-90c7-4d6c9dbb3d4c",
                "mode": "one_time"
            },
            "result": {
                "exit_code": 0,
                "uploads": [
                    {
                        "artifact": "archive",
                        "key": "turbo/uploads/C02ZXXXXXXXX/b1d1a1f0-.../7/sysdiagnose_C02ZXXXXXXXX_20260820-091541.tar.gz",
                        "size": 41264128,
                        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    }
                ]
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
|`run.id`|The run identity, chosen by the agent. Required for a job that uploads: it is what tells two runs of one schedule apart, and it must be the same value the agent used to ask for a destination.|
|`run.mode`|Optional, informational – the correlation is on `schedule_pk` alone.|
|`kind`|The job kind. Optional, but expected: when present it must agree with the resolved schedule, or the entry is skipped. A kind this Zentral does not know is *not* rejected – during a rolling upgrade the instances do not share a set of kinds, and a report of a run that happened must not be dropped. It is skipped with `unknown_job_kind`, and the schedule still records the run.|
|`pk`, `version`|Declarative. The resolved schedule stays authoritative.|
|`result.exit_code`|Scripts – the process exit code, or `null` when the script could not run.|
|`result.status`|mSCP checks – the compliance status code. See [Compliance checks](#compliance-checks).|
|`result.uploads`|One entry for each artifact the run was asked to collect. See [Uploads](#uploads).|

Each entry in `result.uploads` reports one artifact, and it is what closes that upload:

|Attribute|Description|
|---|---|
|`artifact`|**Required.** The artifact name, the same one the agent asked a destination for.|
|`key`|The object key the server minted, echoed back. Zentral compares it with what it minted, and does not accept the upload when the two differ.|
|`size`, `sha256`|What the agent sent. Declarative – the same values were signed into the destination.|
|`truncated`|`true` when the artifact is incomplete because the job hit a limit, for example the `max_size` of a `file_export`.|
|`error`|Present instead of `key` when the artifact did not go up. `error.reason` is one of `expired`, `http_status`, `network`, `too_large` or `mint_rejected`; `error.attempts` and `error.last_http_status` are informational. A reason this release does not know still closes the upload as failed – the artifact is not coming either way.|

An entry that reports an artifact Zentral never minted a destination for is logged and ignored. It never fails the batch: the run happened, and its result is worth keeping.

The `turbo_result` event carries the entries back, each with a `verification` added when [verification](#verification) reached an answer. The event also carries `run.id`, which is what an upload is keyed on.

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

### /public/turbo/uploads/

Ask for a destination for one artifact of one run. See [Uploads](#uploads).

* method: POST
* Content-Type: application/json
* authentication: `Authorization: TurboEnrolledMachine <token>`

Request:

```json
{
    "run": {
        "id": "0f3b06d2-3f4e-4c2a-90c7-4d6c9dbb3d4c",
        "schedule_pk": "b1d1a1f0-8b2a-4a76-9a4a-3a1f1d3b6f22"
    },
    "upload": {
        "artifact": "archive",
        "size": 41264128,
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "digests": {
            "crc64nvme": "9c3fa1075ed248b1"
        }
    }
}
```

The request is built from the blocks of the result. `run` has the names of the `run` of a result entry, and `upload` is an entry of `result.uploads` without its `key`, which Zentral has not built yet. The agent keeps one `run` value and one `upload` value for each artifact, and sends them as they are.

|Attribute|Description|
|---|---|
|`run.id`|**Required.** The run identity, chosen by the agent. The same value must come back in `run.id` in the result.|
|`run.schedule_pk`|**Required.** The schedule the run belongs to. The rules are the ones of the config endpoint: a schedule the agent could not have been served is one it cannot ask a destination for.|
|`upload.artifact`|**Required.** The artifact name, as the job kind declares it.|
|`upload.size`|**Required.** The exact size of the file, in bytes.|
|`upload.sha256`|**Required.** The hex SHA-256 of the file. This is the identity of the artifact for Zentral.|
|`upload.digests`|Optional. The storage digests the config asked for, keyed by algorithm. Each one is in lower-case hex, like `sha256`, and a CRC is its big-endian value: the number written with its leading zeros, 8 characters for `crc32c` and 16 for `crc64nvme`. A little-endian CRC is a `mismatch` on every upload. On Google Cloud Storage, the verification of an upload without its `crc32c` stays `pending`. Necessary for a [multipart](#multipart) artifact: `crc64nvme` is its only validation.|
|`missing_parts`|Resume only. The numbers of the parts that need a URL. The other parts are in the storage, so Zentral accepts the list only for a [multipart](#multipart) upload that has started. It is next to `run` and `upload`, not in `upload`, because a result entry does not have it.|

Response:

```json
{
    "mode": "put",
    "url": "https://bucket.s3.amazonaws.com/turbo/uploads/...&X-Amz-Signature=...",
    "headers": {
        "Content-Type": "application/gzip",
        "Content-Length": "41264128",
        "x-amz-checksum-sha256": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
    },
    "key": "turbo/uploads/C02ZXXXXXXXX/b1d1a1f0-.../7/sysdiagnose_C02ZXXXXXXXX_20260820-091541.tar.gz",
    "expires_at": "2026-08-20T10:15:41+00:00"
}
```

The agent sends the file in one `PUT` to `url`, with every header in `headers`, exactly as given. Those headers are part of the signature: a request that drops one, or changes a value, is refused by the storage. This is how the declared size and the declared digest are enforced without Zentral reading the file.

`key` goes back to Zentral in the result. `expires_at` is when the signature stops being accepted; the signature is verified when the request starts, so an upload that begins in time can finish.

For a [multipart](#multipart) artifact, the response has the part size and one URL for each part, not one `url`:

```json
{
    "mode": "multipart",
    "key": "turbo/uploads/C02ZXXXXXXXX/b1d1a1f0-.../7/sysdiagnose_C02ZXXXXXXXX_20260820-091541.tar.gz",
    "upload_id": "2~kEXAMPLEuploadIDexample",
    "part_size": 67108864,
    "parts": [
        {"n": 1, "url": "https://bucket.s3.amazonaws.com/...&partNumber=1", "headers": {"Content-Length": "67108864"}},
        {"n": 2, "url": "https://bucket.s3.amazonaws.com/...&partNumber=2", "headers": {"Content-Length": "31457280"}}
    ],
    "expires_at": "2026-08-20T10:15:41+00:00"
}
```

|Attribute|Description|
|---|---|
|`upload_id`|The multipart upload at the storage, for the logs. The agent does not send it back.|
|`part_size`|The size of all the parts, but the last. The agent cuts the file with it.|
|`parts[].n`|The part number. The storage needs it, and a resume gives it.|
|`parts[].headers`|The signed length of the part. A part has no checksum: the completion validates the full file.|

The agent sends each part with one `PUT`, and then calls [`/public/turbo/uploads/complete/`](#publicturbouploadscomplete). For a resume, the agent sends the same `run` and `upload` again, with `missing_parts`. The response has only these parts, with the `part_size` and the multipart upload of the upload. A `409` tells the agent that there is no upload to resume: it asks again without `missing_parts`, and sends all the parts.

The same request again, for the same run and the same artifact, returns the same `key` with a new signature. That is the retry: it replaces the object instead of adding a second one. Zentral counts the requests and stops at five. A retry declares the same `size` and `sha256` as the first request: one run and one artifact are one file, and other bytes need a run of their own. Zentral keeps what the first request declared, digests included.

Errors:

|Status|Body|Meaning|
|---|---|---|
|`400`|`{"error": "missing_run"}`, `{"error": "missing_upload"}`|`run` or `upload` is absent, or not an object.|
|`400`|`{"error": "missing_schedule_pk"}`, `{"error": "invalid_schedule_pk"}`|`run.schedule_pk` is absent, or not a UUID.|
|`400`|`{"error": "missing_run_id"}`, `{"error": "invalid_run_id"}`|`run.id` is absent, or not a UUID.|
|`400`|`{"error": "missing_artifact"}`|`upload.artifact` is absent or empty.|
|`400`|`{"error": "invalid_size"}`|`upload.size` is absent, or not a positive integer.|
|`400`|`{"error": "invalid_sha256"}`|`upload.sha256` is absent, or not 64 hexadecimal characters.|
|`400`|`{"error": "invalid_digests"}`|`upload.digests` is not an object, or one of its values is not a hex digest.|
|`400`|`{"error": "missing_digest"}`|The artifact is a [multipart](#multipart) artifact, and `upload.digests.crc64nvme` is absent.|
|`400`|`{"error": "invalid_missing_parts"}`|`missing_parts` is not a list of part numbers, is empty, or gives a part that the upload does not have.|
|`400`|`{"error": "artifact_changed"}`|A retry declares a different `size` or `sha256` than the first request for that run and artifact. That is a different artifact, and it needs its own run.|
|`409`|`{"error": "no_upload_in_flight"}`|`missing_parts` is present, but Zentral has no started multipart upload for this run and artifact. Zentral writes nothing. Ask again without `missing_parts`, and send all the parts.|
|`400`|`{"error": "unknown_artifact"}`|The job does not declare that artifact. Terminal – no retry changes it.|
|`400`|`{"error": "attempts_exhausted"}`|Five destinations were already minted for that run and artifact.|
|`404`|`{"error": "unknown_schedule"}`|The schedule is unknown, belongs to another configuration, is out of scope, or is outside its delivery window.|
|`410`|`{"error": "gate_closed"}`|A result for that one-time job already came back. The job is done on this machine, and an artifact uploaded now could never be referenced.|
|`410`|`{"error": "already_uploaded"}`|The result already reported that artifact as uploaded, or the completion of its [multipart](#multipart) upload is decided.|
|`410`|`{"error": "already_failed"}`|The result already reported that artifact as failed. The run is over for it: a new run gets a new destination.|
|`413`|`{"error": "too_large"}`|`size` is above the limit of the job kind, or above the limit of the deployment.|
|`503`|`{"error": "storage_unavailable"}`|The storage did not answer when Zentral started the [multipart](#multipart) upload. Ask again later.|
|`429`|`{"error": "too_many_pending"}`|The machine holds too many destinations on that schedule that no result has closed. Report the runs already made; a request for a destination the machine already has is never refused for this reason.|

#### The hosted destination

When the deployment has no storage that can sign a `PUT`, the `url` of the response points back at Zentral. The agent sends the same request to it: one `PUT`, with the headers it was given. That destination answers JSON like every other device endpoint.

|Status|Body|Meaning|
|---|---|---|
|`200`|`{}`|The artifact is stored.|
|`400`|`{"error": "size_mismatch"}`|The body is not the size that was declared. A presigned `PUT` has the size in its signature and the storage refuses a mismatch; here Zentral does it.|
|`400`|`{"error": "digest_mismatch"}`|The body is the declared size, and not the declared SHA-256. Checked after the size, which a wrong length fails first and explains better. This is the only point at which a file system storage can check the digest at all: it reports no checksum, so there is nothing to compare later.|
|`403`|`{"error": "invalid_token"}`|The token in the URL is not one Zentral signed, or it expired.|
|`404`|`{"error": "unknown_upload"}`|The token names an upload that does not exist.|
|`409`|`{"error": "already_uploaded"}`|The result already reported that artifact as uploaded.|
|`409`|`{"error": "already_failed"}`|The result already reported that artifact as failed.|
|`413`|`{"error": "too_large"}`|The body is above the body limit of the deployment.|

### /public/turbo/uploads/complete/

Tell Zentral that all the parts of a [multipart](#multipart) upload are sent. Only a multipart upload uses this endpoint: a `mode: "put"` upload is complete when its `PUT` answers.

* method: POST
* Content-Type: application/json
* authentication: `Authorization: TurboEnrolledMachine <token>`

Request: only the identity of the upload. Zentral has the key, the `upload_id` and the part size:

```json
{
    "run": {
        "id": "0f3b06d2-3f4e-4c2a-90c7-4d6c9dbb3d4c",
        "schedule_pk": "b1d1a1f0-8b2a-4a76-9a4a-3a1f1d3b6f22"
    },
    "upload": {
        "artifact": "archive"
    }
}
```

The `run` block of the request for the destination, and the `upload` block with only the artifact name.

Response:

```json
{}
```

The status is `202`, not `200`. Zentral completes the upload in the background, because S3 documents that this can take some minutes. The agent does not wait, and sends its result.

The call is idempotent. Send it again after a timeout or a `5xx`: the completion of a complete upload is a success. If the agent cannot make the call, Zentral asks for the completion when the result of the run arrives.

Errors:

|Status|Body|Meaning|
|---|---|---|
|`400`|`{"error": "missing_run"}`, `{"error": "missing_upload"}`|`run` or `upload` is absent, or not an object.|
|`400`|`{"error": "missing_schedule_pk"}`, `{"error": "invalid_schedule_pk"}`|`run.schedule_pk` is absent, or not a UUID.|
|`400`|`{"error": "missing_run_id"}`, `{"error": "invalid_run_id"}`|`run.id` is absent, or not a UUID.|
|`400`|`{"error": "missing_artifact"}`|`upload.artifact` is absent or empty.|
|`400`|`{"error": "unknown_upload"}`|No upload of that run and artifact for this machine.|
|`400`|`{"error": "not_multipart"}`|The upload is a single `PUT`. It was complete when its `PUT` answered.|
