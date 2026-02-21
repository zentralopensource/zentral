# Core

The Zentral core app supports common functionalities for other apps.

## HTTP API

### `/api/task_result/<uuid:task_id>/`

* method: GET
* required permission: none

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
* required permission: none

Use this endpoint to download the result of a task. A process waiting for a task result should only hit this endpoint when the URL is present in a task response (see [above](#apitask_resulttask_uuid)).

Example:

```
curl -H "Authorization: Token $ZTL_API_TOKEN" \
     -L -o inventory_export_2025-03-12_10-21-12.xlsx \
     https://$ZTL_FQDN/api/task_result/d40e9320-8c0c-459b-bfdb-001a9f73619f/download/
```

### `/api/accounts/token_issuers/oidc/<uuid:issuer_id>/auth/`

* method: POST
* required permission: none

Use this endpoint to exchange an OIDC identity token (Signed JWT) for a short-lived API token.

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
