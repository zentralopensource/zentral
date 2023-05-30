# Export

Zentral provides a REST API to export inventory and application data.

The exported results are available in either `CSV` or `xlsx`format.



## HTTP API

The API offers two endpoints for exporting data.

To initiate the export process, follow these steps:


1. Send a `POST` request to start a background task that aggregates the data. The response will include a UUID `task_id` and `task_result_url`. Save the task_id for subsequent requests.
2. Use a `GET` request to check the export `status` and retrieve the `download_url` when the results are available.
3. Finally, use another `GET` request to download the file or obtain a signed download URL if a cloud storage backend like AWS S3 is configured.


### Authentication

To authenticate API requests, include a token in the  `Authorization` HTTP header.

To obtain a token:

- Create a service account by going to Setup > Manage users as a superuser. In the "Service accounts" subsection, click the `[Create]` button and provide a name for the service account. Save the displayed token securely.
- Alternatively, you can create an API token for a normal user, although this is not recommended. Click on the user in the User list, and use the `[+]` button next to the API token field.



The `Authorization` header should be in the following format:

```
Authorization: Token the_token_string
```

### Requests

#### /api/inventory/machines/export/

* method: `POST`, `GET`

This endpoint exports machine inventory data based on a filter query aligned with the drilldown feature.

You can provide a filter query, such as:

- Default filter `?sf=mbu-t-mis-tp-pf-hm-osv`
- Drilldown filter for including only MACOS devices: `?sf=mbu-t-mis-tp-pf-hm-osv&pf=MACOS`   

Supported data formats: 

* `zip`, `xlsx`

#### /api/inventory/macos_apps/export/

* method: `POST`, `GET`

This endpoint initiates a task to export macOS applications data.

Supported data formats:

* `csv`, `xlsx`

## Example:

### /api/inventory/machines/export/

Export inventory data for machines using a `POST`  request:

```shell
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/inventory/machines/export/?sf=mbu-t-mis-tp-pf-hm-osv&export_format=xlsx
```

Expected response:

```json
{
  "task_id": "978c246a-f8fa-4a9b-b97d-30f6bf385e55",
  "task_result_url": "/api/task_result/978c246a-f8fa-4a9b-b97d-30f6bf385e55/"
}
```

### /api/inventory/macos_apps/export/

Export macOS applications data using a `POST` request:

```shell
$ curl -X POST \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -H 'Content-Type: application/json' \
  https://zentral.example.com/api/inventory/macos_apps/export/
```

Expected response:

```json
{
  "task_id": "8d390c23-11bc-4231-bdab-7e3f513f0d19",
  "task_result_url": "/api/task_result/8d390c23-11bc-4231-bdab-7e3f513f0d19/"
}
```

To check the status of the task and obtain the download_url, use the following GET request:


```shell
$ curl -X GET \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  "https://zentral.example.com/api/task_result/8d390c23-11bc-4231-bdab-7e3f513f0d19/"
```

Expected response:

```shell
{
  "status": "SUCCESS",
  "unready": false,
  "download_url": "/api/task_result/8d390c23-11bc-4231-bdab-7e3f513f0d19/download/"
}
```

Finally, to download the file, use the following `GET` request with the specified download URL:

```shell
$ curl -X GET \
  -H "Authorization: Token $ZTL_API_TOKEN" \
  -O "machines_inventory_export.zip" \
  -L "https://zentral.example.com/api/task_result/8d390c23-11bc-4231-bdab-7e3f513f0d19/download/"
```

The file download should start shortly after executing this request.
