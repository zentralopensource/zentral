---
title: PBAC
weight: 120
---

Zentral uses Policy-Based Access Control to decide what users and service accounts can do in the Web Console and the API. Policies are written in [Cedar](https://www.cedarpolicy.com/), grant *actions* to *principals*, and are evaluated on every authorization check.

## The model

* **Principal**: an authenticated User or Service Account.
* **Role**: a named bucket of access. Principals belong to zero or more Roles. Roles no longer carry permissions directly — they're labels that policies reference.
* **Policy**: a Cedar source stored in the database. A policy grants one or more **actions** to principals matching some condition, typically *"principal is in some Role"*.
* **Action**: the unit of authorization, e.g. `Inventory::Action::"createMachineTag"` or `Realms::Action::"viewRealmGroup"`. Every Zentral endpoint that requires auth declares the action it needs, except the writes of the identity objects (see [What a policy does not give](#what-a-policy-does-not-give)).

Roles are managed under *Roles* in the platform-settings menu. A Role's detail / edit form no longer has a permissions checklist — access is granted by writing a policy that references the Role.

Principals can be added to Roles manually, by a superuser, from the User or Service Account edit form, or automatically through the Realm → Realm Group → Role mapping path; see [SSO Setup](sso.md) for the latter.

## Writing a policy

Create a policy under *Policies* (in the same platform-settings menu as Roles). A policy has a name, a description, an active flag and a Cedar **source**. Policies that are active are evaluated for every authorization check; inactive policies are ignored.

The source is one or more Cedar `permit` (or `forbid`) blocks. The most common shape:

```
permit (
  principal in Role::"<role-pk>",
  action in [<one or more actions>],
  resource
);
```

The `<role-pk>` is the numeric primary key of the Role you want to grant access to. The actions are Cedar action references; see [Finding the action you need](#finding-the-action-you-need) below.

### Action lists must stay in one namespace

Cedar rejects `action in [ ... ]` lists that mix namespaces. To grant actions from two apps (say Realms and Santa), use one `permit` block per namespace:

```
permit (
  principal in Role::"7",
  action in [
    Realms::Action::"viewRealm",
    Realms::Action::"viewRealmGroup"
  ],
  resource
);

permit (
  principal in Role::"7",
  action in [
    Santa::Action::"viewConfiguration"
  ],
  resource
);
```

### Action groups

Each contrib app's actions are members of `<Namespace>::Action::"AdminActions"`, `"UserActions"` and `"ViewerActions"` action groups. Globally, the same buckets exist as `Action::"GlobalAdminActions"`, `Action::"GlobalUserActions"` and `Action::"GlobalViewerActions"` — these aggregate the per-namespace groups so a single reference covers every app.

The three groups are nested. `ViewerActions` contains the read actions. `UserActions` contains the same read actions, and adds the daily operations, for example a machine tag change or a Santa clean sync. `AdminActions` contains all of them, and adds the configuration changes. A role with `UserActions` can thus do all that a role with `ViewerActions` can do.

`Accounts::Action::"viewPolicy"` opens the policies and the Schema browser. The policies show who can do what in the deployment, so this action is a member of the `AdminActions` groups only, and not of `UserActions` or `ViewerActions`. `Accounts::Action::"viewOIDCAPITokenIssuerCondition"` is in the same case: the CEL condition of an OIDC API token issuer shows which workloads get an API token of a service account. The other fields of an issuer stay with `viewOIDCAPITokenIssuer`.

A small number of actions read a secret — the MDM admin password, device lock PIN, FileVault PRK and recovery password. They have a `view` prefix, but they are members of `UserActions` and not of `ViewerActions`.

The `view…Secrets` actions read the passwords, tokens and keys of an object, for example `Stores::Action::"viewStoreSecrets"` for a [store](stores.md#secrets-in-the-api). They are members of `AdminActions` only. They do not give the read of the object: its view action does. Without them, the API returns the hash of each secret in place of its value.

```
// Anyone in this Role can perform every "view" action across every Zentral app.
permit (
  principal in Role::"42",
  action in Action::"GlobalViewerActions",
  resource
);
```

## Worked example

The "Support" role (pk 6) should be able to view everything in the inventory app, and additionally be allowed to create or delete the `YOLO` tag on machines — but not any other tag.

```
permit (
  principal in Role::"6", // Support
  action in Inventory::Action::"ViewerActions",
  resource
);

permit (
  principal in Role::"6", // Support
  action in
    [Inventory::Action::"createMachineTag",
     Inventory::Action::"deleteMachineTag"],
  resource
)
when { context has tagName && context.tagName == "YOLO" };
```

These two actions protect the tags page of a machine. The mass tagging API, `/api/inventory/machines/tags/`, uses `Inventory::Action::"tagAnyMachine"` on the tag instead, and a policy scoped to machines does not limit it.

A fence on a tag thus needs a `forbid` for each path. On the tags page, the tag is in the context. On the mass tagging API, the tag is the resource. These two policies keep a role away from the `VIP` tag (pk 12) on the two paths. They name the tag by its primary key, so they still apply when the tag gets a new name:

```
forbid (
  principal in Role::"6", // Support
  action in
    [Inventory::Action::"createMachineTag",
     Inventory::Action::"deleteMachineTag"],
  resource
)
when { context has tagID && context.tagID == 12 };

forbid (
  principal in Role::"6", // Support
  action == Inventory::Action::"tagAnyMachine",
  resource == Inventory::Tag::"12"
);
```

A `SET` operation of the mass tagging API removes the other tags of its taxonomy. It needs `tagAnyMachine` on each tag of the taxonomy, so the second policy also refuses a `SET` operation on the taxonomy of the `VIP` tag.

The second policy also keeps the role from putting the `VIP` tag in an object that gives its tags to machines later, for example an enrollment or an Osquery query. See [The objects that give tags later](../apps/inventory.md#the-objects-that-give-tags-later) for the list of these objects, and for what Zentral does not decide.

`Inventory::Action::"createTag"` creates a tag. Its resource is the taxonomy of the new tag. For a tag without taxonomy, its resource is `System::"root"`: this entity means "no container", and no other entity is a member of it. This policy lets a role create tags in one taxonomy (pk 3) only, and no tag without taxonomy:

```
permit (
  principal in Role::"6", // Support
  action == Inventory::Action::"createTag",
  resource == Inventory::Taxonomy::"3"
);
```

`Inventory::Action::"viewTag"`, `Inventory::Action::"updateTag"` and `Inventory::Action::"deleteTag"` take the tag, as `tagAnyMachine` does. With `resource in Inventory::Taxonomy::"3"`, a policy gives them for the tags of one taxonomy. `viewTag` limits the list of the tags only: the forms that use tags as a condition show every tag. A move of a tag needs `updateTag` on the tag and `createTag` on the taxonomy that it joins.

A policy with `resource == System::"root"` gives the tags without taxonomy only. `System::"any"` is a different entity: Zentral uses it for the actions that have no resource of their own, and a policy does not need to name it.

Three features worth pointing out:

* **Comments.** `//` opens a single-line Cedar comment — useful for naming the role inline since policies otherwise only carry the numeric pk.
* **Action groups.** `Inventory::Action::"ViewerActions"` is the per-namespace aggregator covering every view-type action the inventory app declares — granting one action group is shorter and more future-proof than enumerating every individual action.
* **Context conditions.** The `when { ... }` clause restricts the second block to requests whose context carries `tagName == "YOLO"`. The `has` guard is mandatory here: `tagName` is declared optional in the inventory action's schema, so writing `context.tagName == "YOLO"` without first checking `context has tagName` makes the Policy form reject the save with *"unable to guarantee safety of access to optional attribute"*.

Whether the `has` guard is needed depends on the action: an attribute an action always sets is declared required, and can be read directly. The Schema browser shows the context of each action, and puts a `?` after the name of the optional attributes. When an attribute accepts a closed set of values, the browser lists them.

```
// Santa::Action::"forceCleanSync" always sets syncType, so no guard is needed.
permit (
  principal in Role::"6",
  action == Santa::Action::"forceCleanSync",
  resource in Inventory::MetaBusinessUnit::"3"
) when { context.syncType == "CLEAN" };
```

Note what the two halves do here: the `resource in` clause restricts *which machines* the role may act on, and the `when` clause restricts *what it may do to them* — this role can rebuild the rule database of the machines in one meta business unit, but never drop the transitive rules a machine created on its own.

The `resource in` clause works because membership is transitive: the action applies to `Inventory::Machine`, and a machine is a member of the meta business units it belongs to. The Schema browser shows the types a principal or a resource is a member of, after the word *in*. A clause can name the type the action declares, or any of those.

Each row has its own action, so a `forbid` on the view action of a container does not hide its rows: forbid the action of the rows, with `resource in` the container. An action that changes or deletes a resource also shows it, so a `forbid` on the view action alone does not hide a resource from a role that can change or delete it ([PBAC rules](../development/pbac-rules.md)).

## What a policy does not give

Until Zentral has a delegated administration, only a superuser, logged in without a Realm, writes the identity objects: the Realms, the users and the service accounts, the roles, the Realm Groups and their members, the Realm Group mappings, the Role mappings, and the API tokens and the token issuers of a service account. A superuser also deletes the API tokens of another user. No policy gives these writes. Each user still manages their own password and verification devices, and their own API tokens, except a superuser, who has none. See [Who can give a Role](sso.md#who-can-give-a-role).

Their write actions are deprecated: for example `Accounts::Action::"createUser"`, `Auth::Action::"updateGroup"` or `Realms::Action::"createRoleMapping"`. They stay in the schema, so that the policies that name them still save, but no page and no API endpoint checks them: they give nothing, whatever the policies say, `Action::"GlobalAdminActions"` included. The Schema browser marks them as deprecated. Remove them from your policies: a later version removes them. Their view actions, for example `Accounts::Action::"viewUser"`, do not change.

The policies themselves have no write action: only a superuser writes them.

## Finding the action you need

Four options, in order of usefulness:

1. **The Schema browser.** Open *Policies* in the platform-settings menu and click *Schema*. It needs `Accounts::Action::"viewPolicy"`. It lists every action Zentral knows about, grouped by namespace. Each action shows what it authorizes, the entity types it applies to, the types those are members of, and the context attributes a `when` clause can read. This is the canonical reference — it always matches the running engine.
2. **The app docs.** Every API endpoint in [`docs/apps/`](../apps/_index.md) lists its `PBAC action(s):` directly under the HTTP method.
3. **The Policy edit form.** Cedar validation rejects unknown action ids with a clear error naming the offending reference, so a save attempt against `Inventory::Action::"crteateMachineTag"` returns *"unrecognized action `Inventory::Action::"crteateMachineTag"`"*.
4. **The `pbac_dump_schema` management command.** It prints the schema of the running engine as one document, in the Cedar human-readable syntax or in the Cedar JSON syntax. Use it to compare two versions of Zentral. It does not include the help text of the Schema browser.

```bash
python server/manage.py pbac_dump_schema --format=human
```

## Existing roles after the migration

When the PBAC engine was introduced, every Role that previously carried Django permissions was auto-converted into a Policy named `Role <role-name>`. That policy lists every action the role had legacy access to, grouped one `permit` block per namespace. Roles created or edited since are blank slates — you grant access by writing a policy that references them.
