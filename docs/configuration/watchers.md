# Watchers

Root key: `apps.zentral.core.watchers` **OPTIONAL**

A **watch** finds the subjects in a bad state and posts an event. It posts one event when a subject becomes degraded, and one more when the subject recovers. It also opens an incident for the subject and closes the incident on the recovery.

Each watch runs on its own schedule. The **watch worker** evaluates them. One worker runs all of the watches, and this section is not necessary.

## `worker_groups`

**OPTIONAL**

A list of groups. Each group is one worker, with a `name` and the `watches` it runs. Use a group to give a watch a process of its own.

```json
{
  "apps": {
    "zentral.core.watchers": {
      "worker_groups": [
        {"name": "inventory", "watches": ["inventory_source_stale"]}
      ]
    }
  }
}
```

The worker of a group runs only the watches the group names. The default worker runs the watches that no group names, so a new watch always has a worker.

A name that is not a watch gives an error in the log. The watch you tried to move stays with the default worker.

## Available watches

| Name | Subject | Reports |
|---|---|---|
| `inventory_source_stale` | a machine and an inventory source | the source stops updating the machine |
| `mdm_push_certificate_expiry` | an APNS push certificate | the certificate comes to its expiry date |
| `munki_agent_unhealthy` | a machine | the Munki agent does not complete its runs |
