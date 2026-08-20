# Core

The Zentral core app supports common functionalities for other apps.

## API authentication

Every Zentral HTTP API request is authenticated with an API token, passed in the `Authorization` HTTP header:

```
Authorization: Token the_token_string
```

A token belongs to a **user** or to a **service account**, and carries that account's privileges — what a token may do is decided by the [PBAC policies](../configuration/pbac.md) that apply to its account, never by the token itself. Tokens are prefixed accordingly: `ztlu_` for a user token, `ztls_` for a service account token.

Zentral only stores a hash of the token, so a token that has been lost cannot be recovered — only replaced. An unknown, malformed or expired token is rejected with a `401`.

### Service accounts

A service account is a Zentral account that cannot sign in to the web console — it exists to hold API credentials. Use one per integration, so that a leaked token can be revoked without disturbing anything else.

To create one, open the **Platform settings** menu (the ⋮ icon in the top right corner), go to *Users*, and click on the [+] button in the *Service accounts* section.

|Field|Description|
|---|---|
|Name|Required. Up to 150 characters: letters, digits and `.`, `+`, `-`, `_`.|
|Description|Optional, free text.|
|Roles|The [roles](../configuration/pbac.md) the account belongs to. You can only grant roles you hold yourself.|

The account's email address is derived from its name and the deployment's `api.fqdn` — you do not set it.

A brand new service account has **no token and no privileges**. Add a token (see below), then write a [PBAC policy](../configuration/pbac.md) granting it the actions it needs. Its detail page shows the principal to reference in that policy, `ServiceAccount::"<pk>"`.

### API tokens

An account can hold several tokens, each with its own name and its own optional expiry. They are listed in a table, with their creation date, expiration date, and an *Active* or *Expired* badge.

* **your own tokens** are managed from *User settings > Profile* (the person icon in the top right corner);
* **a service account's tokens** are managed from its detail page, under *Platform settings > Users*.

To add one, click on the [+] (*Add Token*) button above the token list.

|Field|Description|
|---|---|
|Token name|A descriptive name. It is how you will recognise the token in the list later, and it is recorded in the audit events.|
|Expiry|Optional. Must be a date in the future. Leave it empty for a token that never expires.|

The token is displayed **once**, on the page that follows. Click the eye icon to reveal it, and the clipboard icon to copy it. Once you have stored it — in a password manager, a CI secret, a configuration variable, … — click [Close]. It cannot be retrieved afterwards, but you can always create another one.

Each row in the token list carries a pencil (*Update API Token*) button, which changes the token's name and expiry **without re-issuing it**, and a trash (*Delete API Token*) button, which revokes it immediately.

#### Who can issue a token for whom

Issuing a token means handing out a credential, so Zentral is deliberately restrictive:

* anyone can create a token for **themselves**, from their own profile page;
* **nobody can create a token for another user** — not even a superuser. A user who needs a token creates their own;
* creating a token for a **service account** additionally requires the `Accounts::Action::"createAPIToken"` action *and* holding every role that service account holds. This stops an operator from minting a credential more privileged than themselves. A service account named directly by a PBAC policy can only be issued tokens by a superuser, since its privileges no longer follow from its roles.

The same rule guards the pencil button on a service account's token: pushing an expiry date out keeps a credential alive, so it needs `Accounts::Action::"updateAPIToken"` and the same role check.

Revocation is intentionally easier than issuance: `Accounts::Action::"deleteAPIToken"` is enough to delete any token, with no role check, and you can always delete your own.

### Expiring tokens

A token with an expiration date stops authenticating the moment it passes — requests get a `401` — but the row stays in the list, badged *Expired*, so it is visible rather than silently gone. Rotating a token is therefore: create the new one, deploy it, then delete the old one.

Expired tokens can be purged with a management command:

```bash
python server/manage.py remove_expired_api_tokens
```

|Option|Description|
|---|---|
|`--after-days`|Only purge tokens that expired more than this many days ago. `15` by default.|
|`--user`|Restrict to a username or email address. Repeat the option for several accounts. Every account by default.|
|`--dry-run`|List what would be deleted, and delete nothing.|
|`--json`|JSON output.|

Each deletion emits a `zentral_audit` event, so a purge leaves a trail.

### OIDC API token issuers

A long-lived token in a CI system is a standing liability. As an alternative, a service account can carry one or more **OIDC API token issuers**: a workload that already has an OIDC identity token — a GitHub Actions job, a GitLab pipeline, a cloud workload — exchanges it for a short-lived Zentral API token, and no Zentral secret is stored anywhere.

Issuers are managed from the service account's detail page, under *Platform settings > Users*. They can only be attached to a service account, never to a user.

|Field|Description|
|---|---|
|Name|Required, unique across the deployment.|
|Description|Optional, free text.|
|Issuer URI|The OIDC issuer, `https` only. Zentral derives the discovery URI from it, and uses it to fetch the keys the identity tokens are verified against.|
|Audience|The audience the identity tokens must be issued for.|
|CEL condition|Required. A [CEL](https://cel.dev) expression over the identity token's claims. Only the tokens whose claims satisfy it are accepted.|
|Max API token validity|The longest lifetime, in seconds, of a token this issuer may mint. Between 30 and 604800 (7 days). `3600` by default.|

The CEL condition is evaluated with the verified claims bound to `claims`, and must return a boolean. It is what pins an issuer to the workload you intend — the signature and the audience only prove *a* workload from that provider, so without a claim condition any job on the same provider could mint your token. For a GitHub Actions workflow on a single repository and branch, for example:

```
claims.repository == "acme/infra" && claims.ref == "refs/heads/main"
```

An issuer that does not accept a token — bad signature, wrong audience, or a condition that evaluates to false — returns a `400`.

Once the issuer exists, the workload exchanges its identity token at [`/api/accounts/token_issuers/oidc/<uuid:issuer_id>/auth/`](#apiaccountstoken_issuersoidcuuidissuer_idauth). The tokens it mints are ordinary API tokens with an expiry, and appear in the service account's token list like any other.

Issuers can also be managed over the API — see [`/api/accounts/token_issuers/oidc/`](#apiaccountstoken_issuersoidc).

## HTTP API

### `/api/task_result/<uuid:task_id>/`

* method: GET
* PBAC action: none

Use this endpoint to get the status of a task. If the task generates a file, a `download_url` attribute will be included. The `download_url` will redirect to the exported file (for example, a signed S3 URL if Zentral is configured with a S3 bucket). A process should wait for a task if `unready` is true.

Example:

```
curl -H "Authorization: Token $ZTL_API_TOKEN" \
     https://$ZTL_FQDN/api/task_result/d40e9320-8c0c-459b-bfdb-001a9f73619f/
```

Result:

```json
{
    "name": "zentral.contrib.inventory.tasks.export_inventory",
    "id": "d40e9320-8c0c-459b-bfdb-001a9f73619f",
    "status": "SUCCESS",
    "unready": false,
    "download_url": "/api/task_result/d40e9320-8c0c-459b-bfdb-001a9f73619f/download/",
    "result": {
        "headers": {
            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "Content-Disposition": "attachment; filename=\"inventory_export_2025-03-12_10-21-12.xlsx\""
        }
    }
}
```

### `/api/task_result/<uuid:task_id>/download/`

* method: GET
* PBAC action: none

Use this endpoint to download the result of a task. A process waiting for a task result should only hit this endpoint when the URL is present in a task response (see [above](#apitask_resultuuidtask_id)).

Example:

```
curl -H "Authorization: Token $ZTL_API_TOKEN" \
     -L -o inventory_export_2025-03-12_10-21-12.xlsx \
     https://$ZTL_FQDN/api/task_result/d40e9320-8c0c-459b-bfdb-001a9f73619f/download/
```

### `/api/accounts/token_issuers/oidc/`

The issuers themselves, as described in [OIDC API token issuers](#oidc-api-token-issuers). An issuer can only be attached to a service account, and only by someone allowed to [issue credentials for it](#who-can-issue-a-token-for-whom).

**NB:** creating or updating an issuer fetches the OpenID configuration from the `issuer_uri` to validate it, so the Zentral server needs to be able to reach the provider. An unreachable or non-OpenID URI is a `400`.

#### List all OIDC API token issuers

* method: GET
* PBAC action: `Accounts::Action::"viewOIDCAPITokenIssuer"`
* Optional filter parameter:
    * `name`: name of the issuer
* Optional ordering parameter:
    * `ordering`: `created_at` or `-created_at`. `-created_at` by default.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/accounts/token_issuers/oidc/ \
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
            "id": "4d3fcc26-1509-4221-985e-7da77e1106dc",
            "name": "GitHub Actions - infra",
            "description": "Deploys from the infra repository",
            "issuer_uri": "https://token.actions.githubusercontent.com",
            "audience": "https://zentral.example.com",
            "cel_condition": "claims.repository == \"acme/infra\"",
            "max_validity": 900,
            "created_at": "2026-08-20T13:06:49.861942",
            "updated_at": "2026-08-20T13:06:49.861947",
            "user": 8
        }
    ]
}
```

#### Add an OIDC API token issuer

* method: POST
* Content-Type: application/json
* PBAC action: `Accounts::Action::"createOIDCAPITokenIssuer"`

`user` is the primary key of the service account the issuer mints tokens for.

Example:

issuer.json

```json
{
  "user": 8,
  "name": "GitHub Actions - infra",
  "description": "Deploys from the infra repository",
  "issuer_uri": "https://token.actions.githubusercontent.com",
  "audience": "https://zentral.example.com",
  "cel_condition": "claims.repository == \"acme/infra\"",
  "max_validity": 900
}
```

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST -d @issuer.json \
  https://$ZTL_FQDN/api/accounts/token_issuers/oidc/ \
  |python3 -m json.tool
```

Response (201 Created):

```json
{
    "id": "4d3fcc26-1509-4221-985e-7da77e1106dc",
    "name": "GitHub Actions - infra",
    "description": "Deploys from the infra repository",
    "issuer_uri": "https://token.actions.githubusercontent.com",
    "audience": "https://zentral.example.com",
    "cel_condition": "claims.repository == \"acme/infra\"",
    "max_validity": 900,
    "created_at": "2026-08-20T13:06:49.861942",
    "updated_at": "2026-08-20T13:06:49.861947",
    "user": 8
}
```

### `/api/accounts/token_issuers/oidc/<uuid:pk>/`

#### Get an OIDC API token issuer

* method: GET
* PBAC action: `Accounts::Action::"viewOIDCAPITokenIssuer"`
* `<uuid:pk>`: the primary key of the issuer

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  https://$ZTL_FQDN/api/accounts/token_issuers/oidc/4d3fcc26-1509-4221-985e-7da77e1106dc/ \
  |python3 -m json.tool
```

#### Update an OIDC API token issuer

* method: PUT
* Content-Type: application/json
* PBAC action: `Accounts::Action::"updateOIDCAPITokenIssuer"`
* `<uuid:pk>`: the primary key of the issuer

Send every attribute, `user` included — it is re-checked against your own roles on each update.

#### Delete an OIDC API token issuer

* method: DELETE
* PBAC action: `Accounts::Action::"deleteOIDCAPITokenIssuer"`
* `<uuid:pk>`: the primary key of the issuer

Deleting an issuer stops it minting new tokens. The tokens it already minted stay valid until they expire — delete them from the service account's token list to revoke them now.

Example:

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -X DELETE \
  https://$ZTL_FQDN/api/accounts/token_issuers/oidc/4d3fcc26-1509-4221-985e-7da77e1106dc/
```

Response (204 No Content)

### `/api/accounts/token_issuers/oidc/<uuid:issuer_id>/auth/`

* method: POST
* PBAC action: none — the identity token is the credential

Use this endpoint to exchange an OIDC identity token (Signed JWT) for a short-lived API token. The issuer must be set up first — see [OIDC API token issuers](#oidc-api-token-issuers).

The `jwt` attribute is required. `name` is optional, and names the minted token in the service account's token list. `validity` is optional, in seconds, and must be between 30 and the issuer's *Max API token validity*, which is also the value used when it is omitted.

Example:

```bash
curl -X POST \
     -H 'Content-Type: application/json' \
     -d '{"jwt": "eyJ…", "name": "CI/CD job", "validity": 60}' \
     https://$ZTL_FQDN/api/accounts/token_issuers/oidc/d40e9320-8c0c-459b-bfdb-001a9f73619f/auth/ \
     | python -m json.tool
```

Response:

```json
{
    "id": "8422fe32-3185-4958-a8ca-ae1c4bb52198",
    "expiry": "2026-02-21T13:35:45.925816",
    "name": "CI/CD job",
    "secret": "ztls_0xtePqPLfggHUaAi6NkDVuakz4jtQZ2ObLY3",
    "user": {
        "id": 2,
        "username": "test",
        "email": "test@example.com",
        "is_service_account": true
    }
}
```
