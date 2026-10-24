---
title: PBAC rules for views and endpoints
linkTitle: PBAC rules
weight: 305
---

A view or an endpoint that a typed [PBAC](../configuration/pbac.md) action protects follows these rules. Developers apply them, reviewers check them, and pentesters rate what they find with the [leak classes](#leak-classes).

A view that only a legacy permission protects is not in the scope of these rules. A legacy permission is a decision on `System::"any"`.

## Terms

| Term | Meaning |
| --- | --- |
| Decision | One Cedar request (a principal, one action, one resource, a context) and its answer. |
| Operation | What one view or one endpoint does for one HTTP request. |
| Container | A parent of a resource in the entity graph. For example, the configuration of a Turbo schedule, or the machine and the schedule of an artifact. |
| Page gate | The decision that opens a page. It can be a legacy permission. |
| Row | One item of a list, or of a section of a page. |
| Control | A button or a link that starts an operation. |
| Preview | A decision that Zentral asks before it knows the context, for example before the operator picks the job of a create. Its Deny is final. Its Allow only means "could be permitted". See rule 5. |

## Decisions

1. **One action for each decision.** A decision has one action and one resource. Do not add a decision on another action of the same resource, or of one of its containers, to restrict the first decision.
    - Why: the resource carries its containers and its attributes. A policy on the one action can already say `resource in Turbo::OneTimeJob::"…"` or `resource.job.kind == "file_export"`. A second action makes an admin grant two actions for one operation.
    - Exception: an operation that acts on two resources makes one decision for each resource, with the action that it does to that resource. Cedar calls this compound authorization. Example: a move removes from one container and adds to another.
    - Not an exception: the download of an artifact does not act on its schedule. It needs `downloadJobUpload` only.
2. **Each element of a response has its own decision, with the action of its own resource.** A page is a page gate, rows and controls.
    - The page gate decides the main resource of the page.
    - Example: the *Schedule one-time job* page of a machine. Its URL names the enrolled machine, so `turbo.view_enrolledmachine` is its page gate. The form then decides `createOneTimeJob` on the configuration of the machine. These are two resources, not two actions on one.
    - Each row type has its view action, applied as one filter (rule 6).
    - Each control has the action that it starts: `updateOneTimeJob` for *Edit*, `downloadJobUpload` for *Download*.
    - A row inside a row (an artifact inside a machine row) shows only inside its visible parent. This is layout, not a second decision.
    - Derived data reads rows too: counts, totals, "already used" flags. Compute it from the visible rows only. The [leak classes](#leak-classes) list the accepted exceptions.
3. **Decide once.** Make one decision for each action and resource in one HTTP request.
    - Build the queryset of the visible rows one time. Use it for the rows, the count and the page cut.
    - Batch the decisions of the rows: one Cedar call for the page, not one call for each row.
    - The API detail views cache `get_object()`: the permission class decides on it, and the handler uses it (`PBACRetrieveUpdateDestroyAPIViewWithAudit`).
    - A create makes two different requests: a preview before the validation, and the final decision after it. This is not a duplicate.
4. **Decide before you validate.** The order is: authenticate, resolve the resource of the URL, decide, validate the body, decide the create on the validated data, write.
    - Why: a validation error that comes first tells a refused caller that an object exists, that a value is already used, or what is stored.
    - Before the validation, a create reads only the container from the body (for example `JobScopeResourceSerializer`), for the preview. Rule 13 applies to that read.
5. **A preview never authorizes a write.** A preview is a question that Zentral asks Cedar before it has all the facts of the operation. Its answer can open a form or show a control. Only a second decision, on the validated data, permits the write.
    - When: the create actions carry the new object in their context (rule 10). The *Schedule one-time job* page opens before the operator picks a job. So Zentral asks Cedar with an unknown context, and Cedar answers for all the jobs at once (partial evaluation).
    - Deny: no job can be permitted, for example no policy gives `createOneTimeJob` in this configuration. Zentral hides the control, or answers 403. This answer is final.
    - Allow, or "it depends on the job": at least one job could be permitted. Zentral opens the form, but it has permitted nothing yet.
    - The write: on the submit, Zentral asks again, with the job that the operator picked. Example: a policy permits `sysdiagnose` jobs only. The preview opens the page, and the submit of a `file_export` job gets a 403.
    - In the code: a request with `unknown_context=True`. `PBACViewMixin` and `PBACPermission` refuse a preview as a gate, because its Allow is not a decision. `check_request()` accepts a preview only where Zentral uses its Deny alone.

## Lists and filters

6. **A list filters its rows. It never refuses.** Each row is decided with the view action of its type, before the count and the page cut. A caller without a policy gets an empty list and a 200.
    - Use `pbac.scoping.visible_rows()`. It writes the policies as one SQL filter, or decides each row when a policy is outside the SQL subset. Both give the same rows.
    - No gate on the list: no legacy permission, no "could see any" decision.
    - The list and the detail use the same view action. So the list shows exactly the rows whose detail opens.
7. **A filter treats a hidden id as an unknown id.** An id that does not exist and an id that the caller cannot see give the same answer.
    - API: the filter checks only the type of the value (`UUIDFilter` or `NumberFilter` on the column of the foreign key). It does not load the object. A value of the wrong type is a 400, which tells nothing. An unknown id, a hidden id and an id without visible rows give the same empty list.
    - No second decision on the object of the filter. A policy can give the rows of a container without the view of the container. That caller sees the rows, so the filter must work for that caller too. A decision on the container would refuse it, and add a second action to the list (rule 1).
    - A filter that matches through other rows matches through the visible rows only. Example: the jobs *scheduled in* a configuration, with `turbo.pbac.scheduled_in()`.
    - Console: a select shows the names of its choices, so its choices are a list of another resource, filtered as any list (rule 6). The same choices validate the value, so an unknown id and a hidden id both get "Select a valid choice". Three cases:
        - The resource has a legacy permission: the field needs it, else the field is not on the form. Example: the *Configuration* select of the Turbo schedule lists needs `turbo.view_configuration`.
        - The resource has a typed view action: the choices are `visible_rows(user, <its view request class>, queryset)`. A `ModelChoiceFilter` of django-filter takes a callable queryset that receives the request, for this case.
        - The choices are constants, not resources (a job kind): no decision.
    - Not for a write form. A picker of a write form narrows only the choices that it shows, with the decision of each choice (`OfferAuthorizedJobsMixin`). Its validation keeps all the objects, so a forged post reaches the decision (rules 4 and 5).

## Writes

8. **A write action includes the read of its resource.** A user who can update or delete a resource can see its stored state: the edit form, the delete confirmation, the PUT response and its validation errors.
    - This is a Zentral rule, not a Cedar rule: no policy says it, and no extra decision enforces it. So the [PBAC docs](../configuration/pbac.md) tell policy authors to forbid the write actions of a resource that they want to hide.
    - Why: you cannot change what you cannot see. Without this rule, each write path is a leak to close: the values in the form, the response of the PUT, a "This field cannot be changed" error.
    - Reviewers do not add a view decision to a write path, and do not hide its values. Pentesters rate it as accepted.
    - Cost: a policy cannot make a write-only role. A `forbid` on the view action alone does not hide a resource from a user who can write it. The ADMIN action groups give the view actions and the write actions together.
9. **A PUT carries every attribute.** PATCH is a 405. The update serializer requires every writable field (`FullUpdateSerializerMixin`).
    - A check that reads two fields reads the body only, never the stored value.
    - With rule 8, this rule is about correct writes, not about secrets.

## Policy model

10. **Use a context only for what does not exist yet.** An action on a stored resource has no context. The facts about the resource are its attributes or its containers.
    - A create takes the container as its resource and the new object in its context. `createOneTimeJob` takes the configuration, with the job in `context.job`.
    - Why: the answer for a row then does not change with the request, and `visible_rows()` can write the policies as SQL. Cedar keeps the context for information that is unique to one request.
11. **A typed action is never reachable through `has_perm()`.** A legacy permission maps only to an action on `System`.
    - `register_action()` refuses a legacy permission on an action that takes another resource than `System`.
    - The Django permissions of a model with typed actions map to no action (`pbac_excluded_default_permissions`).
12. **Fail closed.** Cedar skips a policy that errors, so a `forbid` that errors allows.
    - Declare the attributes as required in the schema. Validate each policy when it is saved.
    - The SQL filter writes only the expressions that cannot error. A policy with another expression gets one decision for each row.
    - An input error (NoDecision without a remaining policy) is a Deny. Log every Cedar error.

## Identifiers, answers and logs

13. **A refusal on a guessable id gives the same answer as an unknown id.** The id in the URL or the body of a typed resource is a UUID. Then a 404 (unknown) and a 403 (refused) can differ.
    - Where the id can be guessed (a serial number, an integer key, a name), a refusal gives the answer of an unknown id: a 404 for a URL, a 400 for a body field.
    - Policies name ids that never change: UUIDs, and the URL-safe serial number of a machine.
14. **Log every refusal. Audit every write.** `check_request()` and `PBACPermission` log the refused request. Each write sends an audit event after the commit.
    - A superuser skips Cedar: each decision allows. So a test with a superuser proves nothing about a policy.

## Tests

15. **Test each endpoint with the same matrix.** Each line is one test, for the console and for the API.

| Case | Expected answer | Proves |
| --- | --- | --- |
| No authentication | 401, or the login redirect | Deny by default |
| No policy | 403, or an empty list | Rules 2 and 6 |
| The action alone | Allowed | Rule 1 |
| The action, and a forbid on another action of the same resource | Allowed | Rule 1 |
| The action, and a forbid on each container of the resource | Refused | The containers |
| The action, and a forbid on an attribute (`resource.job.kind`) | Refused | The attributes |
| A refused write with a body that is not valid | 403, not 400 | Rule 4 |
| A list: the SQL filter and the decision for each row | The same rows | Rule 6 |
| A list with 2 rows and with 5 rows | The same number of queries | Rule 3 |
| A filter with an unknown id, a hidden id, and a visible id without rows | The same empty list | Rule 7 |
| A guessable id: unknown, and refused | The same answer | Rule 13 |

## Leak classes

Rate each finding with this table. A defect breaks a rule. An accepted leak is written in the docs.

| Class | Example | Verdict |
| --- | --- | --- |
| Content of a resource that the caller cannot read | A row, a field, a file, a stored value in an error message | Defect |
| A count or a total over hidden rows | "(3)" over a list that shows 1 row | Defect |
| A missing decision, a wrong action, a decision after the validation, a preview used as the final decision | A 400 that names a taken value before the 403 | Defect |
| A decision with two actions | The view of a schedule, and the download of its artifact | Defect (rule 1) |
| Existence of a resource with a guessable id | Is serial number X enrolled? Does the object with the integer id 12 exist? | Defect (rule 13) |
| Existence of a resource with a UUID | A 404 or a 403 on `/api/turbo/one_time_jobs/<uuid>/` | Accepted |
| Existence of hidden rows, through a database constraint | A second recurring job for the same job and configuration. A configuration that cannot be deleted because of its schedules | Accepted, in the docs |
| What a write action shows about its own resource | The edit form, the PUT response | Accepted (rule 8) |

Test with four roles: no policy; one action for each role; all the actions with a forbid on one container, for example one configuration; all the actions with a forbid on one attribute value, for example one job kind. Test each endpoint with each role, and never with a superuser.

## References

- Cedar best practices: [Map actions to the business domain](https://docs.cedarpolicy.com/bestpractices/bp-map-actions.html), [Compound authorization](https://docs.cedarpolicy.com/bestpractices/bp-compound-auth.html), [Using the context](https://docs.cedarpolicy.com/bestpractices/bp-using-the-context.html), [Model all permissions in Cedar](https://docs.cedarpolicy.com/bestpractices/bp-model-all-perms.html), [Avoid mutable identifiers](https://docs.cedarpolicy.com/bestpractices/bp-mutable-identifiers.html).
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) and [OWASP API1:2023 Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization).
- [Google AIP-211: Authorization checks](https://google.aip.dev/211) and [RFC 9110, 403 Forbidden](https://www.rfc-editor.org/rfc/rfc9110#section-15.5.4).
- [django-filter: filter reference](https://django-filter.readthedocs.io/en/stable/ref/filters.html), for the callable queryset of a `ModelChoiceFilter`.
