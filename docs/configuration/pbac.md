# Policy-Based Access Control (PBAC)

Zentral uses Policy-Based Access Control to decide what users and service accounts can do in the Web Console and the API. Policies are written in [Cedar](https://www.cedarpolicy.com/), grant *actions* to *principals*, and are evaluated on every authorization check.

## The model

* **Principal**: an authenticated User or Service Account.
* **Role**: a named bucket of access. Principals belong to zero or more Roles. Roles no longer carry permissions directly — they're labels that policies reference.
* **Policy**: a Cedar source stored in the database. A policy grants one or more **actions** to principals matching some condition, typically *"principal is in some Role"*.
* **Action**: the unit of authorization, e.g. `Inventory::Action::"createMachineTag"` or `Realms::Action::"viewRealmGroup"`. Every Zentral endpoint that requires auth declares the action it needs.

Roles are managed under *Roles* in the platform-settings menu. A Role's detail / edit form no longer has a permissions checklist — access is granted by writing a policy that references the Role.

Principals can be added to Roles manually (from the User or Service Account edit form) or automatically through the Realm → Realm Group → Role mapping path; see [SSO Setup](sso.md) for the latter.

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

Three features worth pointing out:

* **Comments.** `//` opens a single-line Cedar comment — useful for naming the role inline since policies otherwise only carry the numeric pk.
* **Action groups.** `Inventory::Action::"ViewerActions"` is the per-namespace aggregator covering every view-type action the inventory app declares — granting one action group is shorter and more future-proof than enumerating every individual action.
* **Context conditions.** The `when { ... }` clause restricts the second block to requests whose context carries `tagName == "YOLO"`. The `has` guard is mandatory here: `tagName` is declared optional in the inventory action's schema, so writing `context.tagName == "YOLO"` without first checking `context has tagName` makes the Policy form reject the save with *"unable to guarantee safety of access to optional attribute"*.

## Finding the action you need

Three options, in order of usefulness:

1. **The Schema browser.** Open *Policies* in the platform-settings menu and click *Schema*. It lists every action Zentral knows about, grouped by namespace, with the entity types each action applies to. This is the canonical reference — it always matches the running engine.
2. **The app docs.** Every API endpoint in [`docs/apps/`](../apps/) lists its `PBAC action(s):` directly under the HTTP method.
3. **The Policy edit form.** Cedar validation rejects unknown action ids with a clear error naming the offending reference, so a save attempt against `Inventory::Action::"crteateMachineTag"` returns *"unrecognized action `Inventory::Action::"crteateMachineTag"`"*.

## Existing roles after the migration

When the PBAC engine was introduced, every Role that previously carried Django permissions was auto-converted into a Policy named `Role <role-name>`. That policy lists every action the role had legacy access to, grouped one `permit` block per namespace. Roles created or edited since are blank slates — you grant access by writing a policy that references them.
