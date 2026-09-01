# Event stores

Zentral events are persisted and forwarded by **event stores**. Multiple stores can be used at the same time: each event is offered to every store, and each store decides whether to keep it, based on its event filters.

Each store that can write events gets its own queue and its own store worker. One store – the **admin console store** – is also used to fetch the events displayed in the Zentral UI.

## Available backends

| Backend | Options key | Writes events | Admin console | Batching | Terraform |
|---|---|---|---|---|---|
| [`CLICKHOUSE`](#clickhouse) | `clickhouse_kwargs` | yes | yes | 1 – 1000, default 100 | no |
| [`DATADOG`](#datadog) | `datadog_kwargs` | yes | yes | no | no |
| [`ELASTICSEARCH`](#elasticsearch) | `elasticsearch_kwargs` | yes | yes | 1 – 500, default 1 | no |
| [`HTTP`](#http) | `http_kwargs` | yes | no | no, but see `concurrency` | yes |
| [`KINESIS`](#kinesis) | `kinesis_kwargs` | yes | no | 1 – 500, default 1 | yes |
| [`OPENSEARCH`](#opensearch) | `opensearch_kwargs` | yes | yes | 1 – 500, default 1 | no |
| [`PANTHER`](#panther) | `panther_kwargs` | yes | no | 1 – 100, default 1 | yes |
| [`S3_PARQUET`](#s3-parquet) | `s3_parquet_kwargs` | yes | no | 100 – 100000, default 10000 | no |
| [`SNOWFLAKE`](#snowflake) | `snowflake_kwargs` | **no** | yes | n/a | no |
| [`SPLUNK`](#splunk) | `splunk_kwargs` | yes | with `search_url` | 1 – 100, default 1 | yes |
| [`SUMO_LOGIC`](#sumo-logic) | `sumo_logic_kwargs` | yes | no | 1 – 100, default 1 | no |

*Options key* is the object that carries the options of the backend, alongside the [common store options](#common-store-options). *Terraform* indicates whether the [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store) resource covers the backend; its nested attribute is the options key without the `_kwargs` suffix. *Admin console* indicates whether the backend can fetch events back for display in the Zentral UI. Some backends – Datadog, Elasticsearch, OpenSearch and Splunk – can also display links to the events in their own UI; those require extra options, listed in the section of each backend.

The `DATADOG`, `PANTHER`, `SNOWFLAKE`, `SPLUNK` and `SUMO_LOGIC` backends are part of the Zentral Pro Edition.

## Where stores are configured

Stores are **database objects**, not a section of the `base.json` configuration file. There are three ways to manage them:

* the **API**, at `/api/stores/` (see [API](api.md) for the authentication options),
* the [**Zentral Terraform provider**](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs), with the [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store) resource, which is built on that API. It covers four of the backends – see the [backend overview](#available-backends),
* **provisioning**, from the Zentral configuration, for stores that must be deployed with the instance.

The Zentral UI at `/stores/` is **read-only**: it lists the configured stores and displays their settings, with the secrets redacted. The `stores.view_store` permission is required.

A store created by provisioning carries a `provisioning_uid` and can only be changed by updating the configuration: the API refuses to update or delete it, and its `backend` and backend options are omitted from the API representation. Stores created through the API are called *custom* stores, and their number is limited – see [`max_custom_store_count`](#max_custom_store_count).

## Configuration section options

The event store app itself is configured under the `apps` → `zentral.core.stores` key.

### `max_custom_store_count`

**OPTIONAL**

An integer, `3` by default. The maximum number of stores that can be created through the API. Stores created by provisioning are not counted.

### `provisioning`

**OPTIONAL**

A dictionary with a single `stores` key, itself a dictionary of store specifications. The key of each specification is its provisioning UID – a stable identifier of your choosing, used to match a specification with the store it created. Renaming the key on an existing store creates a second store.

```json
{
    …
    "apps": {
        "zentral.core.stores": {
            "max_custom_store_count": 5,
            "provisioning": {
                "stores": {
                    "main-store": {
                        "name": "ClickHouse",
                        "admin_console": true,
                        "backend": "CLICKHOUSE",
                        "clickhouse_kwargs": {
                            "host": "clickhouse.example.com",
                            "password": "{{ env:CLICKHOUSE_PASSWORD }}"
                        }
                    }
                }
            }
        }
    }
}
```

The standard configuration substitutions are available for every value: `"{{ env:ENV_VAR_NAME }}"` to read an environment variable, `"{{ file:FILE_PATH }}"` to read a file, and `"{{ secret:NAME_OF_THE_SECRET }}"` to read an AWS or GCP secret. Use them for the secrets – they are encrypted with the configured [secret engine](secret_engines.md) when the store is saved.

## Common store options

These options apply to every store, whatever the backend, and are used both by the API and by provisioning.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | **yes** | | A unique name. Its slugified form must be unique too – it is used to derive the name of the store queue on some queue backends. |
| `description` | string | no | `""` | A free-form description. |
| `admin_console` | boolean | no | `false` | Use this store to fetch the events displayed in the Zentral UI. Only **one** store can have it, and its backend must support reading events – see the [backend overview](#available-backends). |
| `event_filters` | object | no | `{}` | Which events the store keeps. See [`event_filters`](#event_filters). |
| `events_url_authorized_roles` | list | no | `[]` | Restrict the links to the events in the store to the members of these [roles](pbac.md). Empty means all users get the links. In the API, roles are referenced by primary key; in a provisioning specification, by the provisioning UID of a provisioned role. |
| `backend` | string | **yes** | | The backend, as an upper-case identifier. See the [backend overview](#available-backends). |
| `<backend>_kwargs` | object | **yes** | | The options of the chosen backend. Exactly one such key must be present, and it must be the one matching `backend` – for example `splunk_kwargs` for the `SPLUNK` backend. |

### `event_filters`

An object with two optional keys, `excluded_event_filters` and `included_event_filters`. In Terraform, this is the [`event_filters`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store#nestedatt--event_filters) attribute of `zentral_store`. Each is a list of filters, and each filter is an object with optional `tags`, `event_type` and `routing_key` attributes, whose values are non-empty lists of strings.

```json
{
  "event_filters": {
    "excluded_event_filters": [
      {"tags": ["munki", "santa"]},
      {"event_type": ["osquery_result"], "routing_key": ["important"]},
      {"event_type": ["zentral_login", "zentral_logout"]}
    ]
  }
}
```

With these filters, the following events are excluded:

* `munki` **or** `santa` tagged events
* `osquery_result` events **with** the `important` `routing_key` value
* `zentral_login` **or** `zentral_logout` events

Boolean combinations: arrays/lists → `OR`, dictionaries/objects → `AND`.

* Within `excluded_event_filters` – or `included_event_filters` – the different filters are combined using the `OR` operator.
* Within each filter, the different attributes must all match (`AND`).
* For each filter attribute, at least one value must match (`OR`).

The `excluded_event_filters` **take precedence** over the `included_event_filters`. If an event is a match for the `excluded_event_filters`, the `included_event_filters` are not evaluated, and the event is excluded.

If neither `excluded_event_filters` nor `included_event_filters` is set, all events are included in the store.

## Backend options

One section per backend, listing what goes in its `<backend>_kwargs` object.

### ClickHouse

The events table, a few aggregation tables and their materialized views are created by Zentral when the store worker starts. The events table is partitioned by day, and the events expire after `ttl_days`. The aggregation tables – used for the event type and tag histograms, and for the machine heartbeats – have their own fixed retention of 31 days.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `host` | string | **yes** | | The ClickHouse host. |
| `port` | integer | no | `8443` | 1 – 65535. |
| `secure` | boolean | no | `true` | Use HTTPS. |
| `verify` | boolean | no | `true` | Verify the TLS certificate. |
| `compress` | boolean | no | `true` | Compress the requests and responses. |
| `username` | string | no | | Used with `password`. |
| `password` | string | no | `""` | **Secret.** Used with `username`. |
| `access_token` | string | no | | **Secret.** JWT access token. Cannot be combined with `username` or `password`. |
| `database` | string | no | `default` | Must match `^[a-zA-Z_][0-9a-zA-Z_]*$`. |
| `table_name` | string | no | `zentral_events` | Must match `^[a-zA-Z_][0-9a-zA-Z_]*$`. |
| `table_engine` | string | no | `MergeTree` | Must match `^[a-zA-Z_][0-9a-zA-Z_]*$`. |
| `ttl_days` | integer | no | `90` | Minimum 1. How long the events are kept. |
| `connect_timeout` | integer | no | `10` | In seconds. Minimum 1. |
| `send_receive_timeout` | integer | no | `300` | In seconds. Minimum 1. |
| `batch_size` | integer | no | `100` | 1 – 1000. |

#### Example

```json
{
    "name": "ClickHouse",
    "admin_console": true,
    "backend": "CLICKHOUSE",
    "clickhouse_kwargs": {
        "host": "clickhouse.example.com",
        "username": "zentral",
        "password": "{{ env:CLICKHOUSE_PASSWORD }}",
        "database": "zentral",
        "ttl_days": 400,
        "batch_size": 500
    }
}
```

### Datadog

Events are sent to the Datadog log intake. Reading the events back – required for the admin console store – uses the Datadog log API, and needs an `application_key` in addition to the `api_key`.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `site` | string | **yes** | | One of `datadoghq.com`, `us3.datadoghq.com`, `us5.datadoghq.com`, `datadoghq.eu`, `ddog-gov.com`, `ap1.datadoghq.com`, `ap2.datadoghq.com`. See the [Datadog site documentation](https://docs.datadoghq.com/getting_started/site/). |
| `api_key` | string | **yes** | | **Secret.** Used to send the events. |
| `application_key` | string | no | | **Secret.** Required to read the events back, i.e. to use the store as the admin console store. |
| `service` | string | no | `Zentral` | The `service` value of the Datadog logs. |
| `source` | string | no | `zentral` | The `ddsource` value of the Datadog logs. |

Links to the events in the Datadog UI are always available.

#### Example

```json
{
    "name": "Datadog",
    "admin_console": true,
    "backend": "DATADOG",
    "datadog_kwargs": {
        "site": "datadoghq.eu",
        "api_key": "{{ env:DATADOG_API_KEY }}",
        "application_key": "{{ env:DATADOG_APPLICATION_KEY }}",
        "service": "zentral.example.com"
    }
}
```

### Elasticsearch

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `hosts` | list of strings | **yes** | | At least one `http://` or `https://` URL. |
| `verify_certs` | boolean | no | `true` | Verify the TLS certificates. |
| `ssl_show_warn` | boolean | no | `true` | Display a warning when the TLS certificates are not verified. |
| `username` | string | no | | Basic authentication. Requires `password`. |
| `password` | string | no | | **Secret.** Basic authentication. Requires `username`. |
| `index` | string | no | | The index the events are written to. Mutually exclusive with `indices`; one of the two is required. |
| `indices` | list of objects | no | | Multiple indices, chosen per event. See [Multiple indices](#multiple-indices). |
| `read_index` | string | no | `index` | The index or alias used to read the events back. **Required** when `indices` is used. |
| `number_of_shards` | integer | no | `1` | Minimum 1. Used when Zentral creates an index. |
| `number_of_replicas` | integer | no | `0` | Minimum 0. Used when Zentral creates an index. |
| `batch_size` | integer | no | `1` | 1 – 500. |
| `kibana_discover_url` | string | no | | For example `https://kibana.example.com/app/discover`. If set, links to the events in Kibana are displayed in the Zentral UI. |
| `kibana_index_pattern_uuid` | string | no | | The UUID of the Kibana data view used in those links. |

#### Multiple indices

Instead of a single `index`, a list of `indices` can be configured, so that different events land in different indices – to give them a different retention or a different storage class, for example.

Each entry is an object with a `name`, a `priority` and, optionally, `included_event_filters` and `excluded_event_filters` – the same filter syntax as [`event_filters`](#event_filters). For each event, the matching index with the highest priority wins.

* All the names must be different, and all the priorities must be different.
* The index with the **lowest** priority is the default index. It **cannot** be filtered, so that no event is left without an index.
* `read_index` is required, and should point to an alias covering every index you want to search from the Zentral UI.

#### Example

```json
{
    "name": "Elasticsearch",
    "admin_console": true,
    "backend": "ELASTICSEARCH",
    "elasticsearch_kwargs": {
        "hosts": ["https://elasticsearch.example.com:9200"],
        "username": "zentral",
        "password": "{{ env:ELASTICSEARCH_PASSWORD }}",
        "batch_size": 100,
        "indices": [
            {"name": "zentral-osquery", "priority": 10,
             "included_event_filters": [{"tags": ["osquery"]}]},
            {"name": "zentral-other", "priority": 1}
        ],
        "read_index": "zentral-all",
        "kibana_discover_url": "https://kibana.example.com/app/discover",
        "kibana_index_pattern_uuid": "00000000-0000-0000-0000-000000000000"
    }
}
```

### HTTP

Terraform resource: [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store), with an [`http`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store#nestedatt--http) attribute.

Events are POSTed one by one, as JSON, to an arbitrary endpoint.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `endpoint_url` | string | **yes** | | The `http://` or `https://` URL the events are POSTed to. For example `https://acme.service-now.com/api/now/import/zentral_events`. |
| `verify_tls` | boolean | no | `true` | Verify the TLS certificate. |
| `username` | string | no | | Basic authentication. Requires `password`. |
| `password` | string | no | | **Secret.** Basic authentication. Requires `username`. |
| `headers` | list of objects | no | `[]` | Extra headers, each an object with a `name` and a `value`. **The values are secrets.** The `Content-Type` header is set to `application/json`. An `Authorization` header cannot be combined with `username`/`password`. |
| `request_timeout` | integer | no | `120` | In seconds. 1 – 600. |
| `max_retries` | integer | no | `3` | 1 – 5. |
| `concurrency` | integer | no | `1` | 1 – 20. The number of threads used to post the events, to increase the throughput of the store worker. **Only works with the AWS SNS/SQS queues backend.** |

#### Example

```json
{
    "name": "ServiceNow",
    "backend": "HTTP",
    "event_filters": {
        "included_event_filters": [
            {"event_type": ["add_machine", "add_machine_os_version", "remove_machine_os_version"]}
        ]
    },
    "http_kwargs": {
        "endpoint_url": "https://acme.service-now.com/api/now/import/zentral_events",
        "username": "Zentral",
        "password": "{{ env:SERVICE_NOW_API_PASSWORD }}",
        "concurrency": 5
    }
}
```

### Kinesis

Terraform resource: [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store), with a [`kinesis`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store#nestedatt--kinesis) attribute.

This store is capable of batch operation. The maximum `batch_size` is 500. See the [`kinesis:PutRecords`](https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html) documentation for more details.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `stream` | string | **yes** | | The name of the Kinesis stream. |
| `region_name` | string | **yes** | | The AWS region of the stream. |
| `serialization_format` | string | **yes** | | `zentral` for the Zentral canonical serialization, or `firehose_v1` for a format optimized for Kinesis Firehose. |
| `aws_access_key_id` | string | no | | Requires `aws_secret_access_key`. Cannot be combined with `assume_role_arn`. |
| `aws_secret_access_key` | string | no | | **Secret.** Requires `aws_access_key_id`. |
| `assume_role_arn` | string | no | | The ARN of a role to assume. Cannot be combined with `aws_access_key_id`. |
| `batch_size` | integer | no | `1` | 1 – 500. |

#### AWS authentication and authorization

When operating in AWS, it is recommended to use a role attached to the EC2 instance or to the container to authenticate the calls to the Kinesis API, and to leave `aws_access_key_id` and `aws_secret_access_key` empty.

Example of an IAM policy to allow Zentral to write to the Kinesis stream:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKinesisPut",
            "Action": [
                "kinesis:PutRecords",
                "kinesis:PutRecord"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:kinesis:<AWS_REGION>:<AWS_ACCOUNT_ID>:stream/<KINESIS_STREAM_NAME>"
        }
    ]
}
```

The `PutRecord` action can be omitted if the store is configured for batch operations, i.e. with a `batch_size` greater than 1.

#### Example

```json
{
    "name": "Kinesis",
    "backend": "KINESIS",
    "kinesis_kwargs": {
        "stream": "name_of_the_stream",
        "region_name": "us-east-1",
        "serialization_format": "firehose_v1",
        "assume_role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/<NAME_OF_THE_ROLE>",
        "batch_size": 500
    }
}
```

### OpenSearch

Use this store with a managed AWS OpenSearch domain. It takes all the [Elasticsearch options](#elasticsearch) – including [multiple indices](#multiple-indices) – plus `aws_auth`, to sign the API calls with the standard AWS signatures.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `aws_auth` | object | no | | If omitted, the API calls are not signed. Cannot be combined with `username`/`password`. |
| `aws_auth.region_name` | string | **yes** | | The AWS region of the OpenSearch domain. Required when `aws_auth` is used. |
| `aws_auth.aws_access_key_id` | string | no | | Requires `aws_auth.aws_secret_access_key`. |
| `aws_auth.aws_secret_access_key` | string | no | | **Secret.** Requires `aws_auth.aws_access_key_id`. |

It is recommended to use a role attached to the EC2 instance or to the container, and to leave `aws_auth.aws_access_key_id` and `aws_auth.aws_secret_access_key` empty: when they are, the credentials are resolved with the [default boto3 mechanisms](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html).

Use `kibana_discover_url` and `kibana_index_pattern_uuid` for the OpenSearch Dashboards, for example `https://example-00000000000000000000000000.us-east-1.es.amazonaws.com/_dashboards`.

#### Example

```json
{
    "name": "OpenSearch",
    "admin_console": true,
    "backend": "OPENSEARCH",
    "opensearch_kwargs": {
        "hosts": ["https://example-00000000000000000000000000.us-east-1.es.amazonaws.com"],
        "index": "zentral-events",
        "batch_size": 100,
        "kibana_discover_url": "https://example-00000000000000000000000000.us-east-1.es.amazonaws.com/_dashboards",
        "kibana_index_pattern_uuid": "00000000-0000-0000-0000-000000000000",
        "aws_auth": {"region_name": "us-east-1"}
    }
}
```

### Panther

Terraform resource: [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store), with a [`panther`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store#nestedatt--panther) attribute.

Zentral can send events to a Panther HTTP log source, with Bearer authentication. A custom schema must be configured in Panther – use [`schema.yml`](https://github.com/zentralopensource/zentral/tree/main/ee/zentral/core/stores/backends/panther/schema.yml) from the Zentral repository.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `endpoint_url` | string | **yes** | | The Panther [HTTP Log Source](https://docs.panther.com/data-onboarding/data-transports/http) URL. For example `https://logs.example.runpanther.net/http/00000000-0000-0000-0000-000000000000`. |
| `bearer_token` | string | **yes** | | **Secret.** The token used for Bearer authentication. |
| `batch_size` | integer | no | `1` | 1 – 100. |

#### Example

```json
{
    "name": "Panther",
    "backend": "PANTHER",
    "panther_kwargs": {
        "endpoint_url": "https://logs.example.runpanther.net/http/00000000-0000-0000-0000-000000000000",
        "bearer_token": "{{ env:PANTHER_BEARER_TOKEN }}",
        "batch_size": 100
    }
}
```

### S3 Parquet

Events are batched and written to an S3 bucket as Parquet files, for querying with Athena, Snowflake, DuckDB, … Each file is written to `<prefix>/<YYYY>/<MM>/<DD>/<writer id>/<batch index>.parquet`, where the writer ID is unique to each store worker run.

This backend **only** operates in batch mode: `batch_size` cannot be lower than 100. The `max_batch_age_seconds` option bounds how long a partial batch is held before being flushed.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `bucket` | string | **yes** | | The name of the S3 bucket. |
| `region_name` | string | **yes** | | The AWS region of the bucket. |
| `prefix` | string | no | `""` | A prefix for the object keys. Include the trailing `/` if you want one. |
| `aws_access_key_id` | string | no | | Requires `aws_secret_access_key`. Cannot be combined with `assume_role_arn`. |
| `aws_secret_access_key` | string | no | | **Secret.** Requires `aws_access_key_id`. |
| `assume_role_arn` | string | no | | The ARN of a role to assume. Cannot be combined with `aws_access_key_id`. |
| `batch_size` | integer | no | `10000` | 100 – 100000. The number of events per Parquet file. |
| `max_batch_age_seconds` | integer | no | `300` | 10 – 1200. How long a partial batch is held before it is written. |

As with the other AWS backends, it is recommended to use a role attached to the EC2 instance or to the container, and to leave `aws_access_key_id` and `aws_secret_access_key` empty. The role must be allowed to perform the `s3:PutObject` action on the bucket.

#### Example

```json
{
    "name": "S3 Parquet",
    "backend": "S3_PARQUET",
    "s3_parquet_kwargs": {
        "bucket": "acme-zentral-events",
        "prefix": "events/",
        "region_name": "us-east-1",
        "batch_size": 50000,
        "max_batch_age_seconds": 600
    }
}
```

### Snowflake

The Snowflake backend is **read-only**: it has no store worker, and can only be used as the admin console store. To get the events into Snowflake, set up a pipeline with the [Kinesis](#kinesis) or [S3 Parquet](#s3-parquet) backend – with Kinesis Firehose or Snowpipe, for example.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `account` | string | **yes** | | The name of the Snowflake account. |
| `user` | string | **yes** | | The name of the Snowflake user. |
| `password` | string | **yes** | | **Secret.** The password of the Snowflake user. |
| `database` | string | **yes** | | The name of the Snowflake database. |
| `role` | string | **yes** | | The name of the Snowflake role. |
| `warehouse` | string | **yes** | | The name of the Snowflake warehouse. |
| `schema` | string | no | `PUBLIC` | The name of the Snowflake schema. |
| `session_timeout` | integer | no | `13800` | In seconds, minimum 60. Defaults to 4 hours – the Snowflake default – minus 10 minutes. After the current session has timed out, a new connection is established if necessary. |

#### Example

```json
{
    "name": "Snowflake",
    "admin_console": true,
    "backend": "SNOWFLAKE",
    "snowflake_kwargs": {
        "account": "acme",
        "user": "ZENTRAL",
        "password": "{{ env:SNOWFLAKE_PASSWORD }}",
        "database": "ZENTRAL",
        "schema": "ZENTRAL",
        "role": "ZENTRAL",
        "warehouse": "DEFAULTWH"
    }
}
```

### Splunk

Terraform resource: [`zentral_store`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store), with a [`splunk`](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs/resources/store#nestedatt--splunk) attribute.

Events are written with the Splunk HTTP Event Collector. Two optional extras are available:

* set `search_app_url` to display links to the events in the Splunk UI,
* set both `search_url` and `search_token` to let Zentral fetch the events back, i.e. to use the store as the admin console store.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `hec_url` | string | **yes** | | The base URL of the Splunk HTTP Event Collector, for example `https://splunk.example.com:8088`. The path to the collector endpoint **must not** be included. |
| `hec_token` | string | **yes** | | **Secret.** The HEC token. |
| `hec_extra_headers` | list of objects | no | `[]` | Extra headers for the HEC requests, each an object with a `name` and a `value`. **The values are secrets.** Can be used to authenticate with a proxy. The `Authorization` and `Content-Type` headers **cannot** be changed. |
| `hec_request_timeout` | integer | no | `300` | In seconds, minimum 1. |
| `hec_index` | string | no | | The name of the Splunk index. Do not use it if the index is set by the HEC. |
| `hec_source` | string | no | | The `source` of the Splunk events. Do not use it if the source is set by the HEC. |
| `batch_size` | integer | no | `1` | 1 – 100. |
| `serial_number_field` | string | no | `machine_serial_number` | The Splunk event field used for the machine serial number. |
| `computer_name_as_host_sources` | list of strings | no | `[]` | Inventory source names used to find a hostname to set as the `host` value of the Splunk event. The first source with a non-empty value wins. Empty means the machine serial number is used. |
| `custom_host_field` | string | no | | If set, the event metadata host field value is copied to this event field. |
| `verify_tls` | boolean | no | `true` | Verify the TLS certificates, for both the HEC and the search requests. |
| `search_app_url` | string | no | | The URL of the Splunk search app, for example `https://splunk.example.com/en-US/app/search/search`. If set, links to the events in Splunk are displayed in the Zentral UI. |
| `search_url` | string | no | | The base URL of the Splunk API server, for example `https://splunk.example.com:8089`. With `search_token`, allows the store to be used as the admin console store. |
| `search_token` | string | no | | **Secret.** The authentication token for the Splunk API server. With `search_url`, allows the store to be used as the admin console store. |
| `search_extra_headers` | list of objects | no | `[]` | Extra headers for the search API requests, each an object with a `name` and a `value`. **The values are secrets.** The `Authorization` and `Content-Type` headers **cannot** be changed. |
| `search_index` | string | no | | If set, an `index` filter is added to the search jobs and URLs. |
| `search_source` | string | no | | If set, a `source` filter is added to the search jobs and URLs. Use this for example if a single Splunk index is used for multiple Zentral instances. |
| `search_request_timeout` | integer | no | `300` | In seconds, minimum 1. |

#### Example

```json
{
    "name": "Splunk",
    "admin_console": true,
    "backend": "SPLUNK",
    "splunk_kwargs": {
        "hec_url": "https://splunk.example.com:8088",
        "hec_token": "{{ env:SPLUNK_HEC_TOKEN }}",
        "hec_extra_headers": [
            {"name": "CF-Access-Client-Id", "value": "123"},
            {"name": "CF-Access-Client-Secret", "value": "{{ env:SPLUNK_HEC_CF_ACCESS_CLIENT_SECRET }}"}
        ],
        "hec_request_timeout": 30,
        "hec_index": "zentral",
        "hec_source": "zentral.example.com",
        "batch_size": 100,
        "serial_number_field": "serial_number",
        "computer_name_as_host_sources": ["santa", "osquery"],
        "search_app_url": "https://splunk.example.com/en-US/app/search/search",
        "search_url": "https://splunk.example.com:8089",
        "search_token": "{{ env:SPLUNK_SEARCH_TOKEN }}",
        "search_extra_headers": [
            {"name": "CF-Access-Client-Id", "value": "456"},
            {"name": "CF-Access-Client-Secret", "value": "{{ env:SPLUNK_SEARCH_CF_ACCESS_CLIENT_SECRET }}"}
        ],
        "search_source": "zentral.example.com",
        "verify_tls": true
    }
}
```

### Sumo Logic

Events are sent to a Sumo Logic HTTP collector.

| Option | Type | Required | Default | Description |
|---|---|---|---|---|
| `collector_url` | string | **yes** | | **Secret.** The URL of the Sumo Logic HTTP source. It carries the authentication, and is stored encrypted. |
| `batch_size` | integer | no | `1` | 1 – 100. |

#### Example

```json
{
    "name": "Sumo Logic",
    "backend": "SUMO_LOGIC",
    "sumo_logic_kwargs": {
        "collector_url": "{{ env:SUMO_LOGIC_COLLECTOR_URL }}",
        "batch_size": 100
    }
}
```
