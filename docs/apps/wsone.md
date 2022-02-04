# Workspace ONE

[Workspace ONE](https://www.vmware.com/content/vmware/vmware-published-sites/us/products/workspace-one.html.html) is a unified endpoint management solution. Zentral can use multiple Workspace ONE instances as inventory sources.

## Configuration

To activate the Workspace ONE module, you need to add an empty `zentral.contrib.wsone` subsection to the `apps` section in `base.json`.

```json
{
  "apps": {
    "zentral.contrib.wsone": {}
  }
}
```

### Create an instance

Once the module has been activated, you can connect Zentral to a Workspace ONE deployment. Before you can create a Workspace ONE instance in Zentral, you need to gather the following information:

|attribute|value7
|---|---|
|Server URL|The base URL to connect to the Workspace ONE deployment. It usually follows this pattern: `https://SUBDOMAIN.awmdm.com`.|
|API key|The Workspace ONE [API Key](https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/2011/AirLift_Configuration/GUID-AWT-AIRLIFT-RESTAPI.html).|
|Client ID|The OAuth Client ID. Zentral uses OAuth to authenticate with Workspace ONE. You need to [register a new OAuth client](https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/services/UEM_ConsoleBasics/GUID-BF20C949-5065-4DCF-889D-1E0151016B5A.html#create-an-oauth-client-to-use-for-api-commands-saas-3) in Workspace ONE, and assign it a role.|
|Client secret|The OAuth Client secret. See Client ID.|
|Token URL|The [region specific Token URL](https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/services/UEM_ConsoleBasics/GUID-BF20C949-5065-4DCF-889D-1E0151016B5A.html#datacenter-and-token-urls-for-oauth-20-support-2) for the OAuth authentication.|

* Go to `Setup > WSOne > Instances`, click on the `Create` button.
* Select a business unit.
* Copy the required information (see above).
* Pick a username and password. They will be used by Workspace ONE to authenticate the event notification requests to Zentral (HTTP Basic Authentication).
* **OPTIONAL** Enter a comma separated list of Workspace ONE organization group names (case-sensitive) in the `Excluded groups` field. Devices assigned to those groups or any of their children in Workspace ONE will not be synchronized.

### Configure the Workspace ONE event notifications

To receive events in Zentral, and trigger the automatic device synchronizations, you need to [configure the Event Notifications](https://docs.vmware.com/en/VMware-Workspace-ONE-UEM/2102/System_Settings_On_Prem/GUID-AWT-SYSTEM-ADVANCED-API-NOTIF.html) in Workspace ONE:

* `Target URL`, `User Name`, `Password`: use the information available in the *Event notifications* section of the Zentral Workspace ONE instance detail page.
* **IMPORTANT** Set `Format` to `JSON`.
* Select the events you want to send to Zentral.

## HTTP API

### `/api/wsone/instances/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `wsone.view_instance`

Use this endpoint to list all available Zentral Workspace ONE instances.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/wsone/instances/ \
  |python -m json.tool
```

Response:

```json
[
  {
    "id": 1,
    "business_unit": 1,
    "client_id": "d2186IFnISnulzGIIwHOAJ68opAWUnFc",
    "server_url": "https://cn000.awmdm.com",
    "excluded_groups": ["iPads"],
    "version": 12,
    "created_at": "2022-01-18T16:07:59.826640",
    "updated_at": "2022-01-19T09:25:20.530703"
  }
]
```

### `/api/wsone/instances/{id}/`

* method: GET
* Content-Type: application/json
* required permissions:
    * `wsone.view_instance`

Use this endpoint to get a specific Zentral Workspace ONE instance.

```bash
curl \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/wsone/instances/1/ \
  |python -m json.tool
```

Response:

```json
{
  "id": 1,
  "business_unit": 1,
  "client_id": "d2186IFnISnulzGIIwHOAJ68opAWUnFc",
  "server_url": "https://cn000.awmdm.com",
  "excluded_groups": ["iPads"],
  "version": 12,
  "created_at": "2022-01-18T16:07:59.826640",
  "updated_at": "2022-01-19T09:25:20.530703"
}
```

### `/api/wsone/instances/{id}/sync/`

* method: POST
* Content-Type: application/json
* required permissions:
    * `wsone.view_instance`
    * `inventory.change_machinesnapshot`

Use this endpoint to start the inventory synchronization for a specific Zentral Workspace ONE instance. A task id and URL to check the synchronization task status will be returned.

```bash
curl \
  -XPOST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/wsone/instances/1/sync/ \
  |python -m json.tool
```

Response:

```json
{
  "task_id": "b1512b8d-1e17-4181-a1c3-93a7243fddd3",
  "task_result_url": "/api/task_result/b1512b8d-1e17-4181-a1c3-93a7243fddd3/"
}
```
