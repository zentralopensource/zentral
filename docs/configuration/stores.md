# Event stores configuration section

Zentral events are stored using instances of the event store backends. Multiple stores can be used at the same time. Some configuration options are common to all the store backends, and some are specific to each backend.

To define a store, a backend configuration needs to be added to the base.json `stores` dictionary. A unique identifier is used as the key, and the configuration is a dictionary. For example:

```json
{
    …
    "stores": {
        "elasticseach": {
            "backend": "zentral.core.stores.backends.elasticsearch"
            …
        }
    }
}
```

## Common backend options

### `backend`

**MANDATORY**

The python module implementing the store, as a string. Currently available:

* `zentral.core.stores.backends.azure_log_analytics`
* `zentral.core.stores.backends.datadog`
* `zentral.core.stores.backends.elasticsearch`
* `zentral.core.stores.backends.http`
* `zentral.core.stores.backends.humio`
* `zentral.core.stores.backends.kinesis`
* `zentral.core.stores.backends.opensearch`
* `zentral.core.stores.backends.panther`
* `zentral.core.stores.backends.snowflake`
* `zentral.core.stores.backends.splunk`
* `zentral.core.stores.backends.sumo_logic`
* `zentral.core.stores.backends.syslog`

### `frontend`

**OPTIONAL**

A boolean indicating if the store is the main event store to be used to fetch events in the Zentral UI. Only one store can be set as the `frontend` store, and ATM, only the `datadog`, `elasticsearch` and `splunk` backends support fetching events for display in the UI.

### `excluded_event_filters`

**OPTIONAL**

A list of filters used to exclude events from the store. Each filter is a dictionary/object. Filters can have `tags`, `event_type` and `routing_key` attributes. Each filter attribute is a list of strings. For example:

```json
{
  "excluded_event_filters": [
    {"tags": ["munki", "santa"]},
    {"event_type": ["osquery_result"], "routing_key": ["important"]},
    {"event_type": ["zentral_login", "zentral_logout"]}
  ]
}
```

With these filters, the following events are excluded:

* `munki` **or** `santa`tagged events
* `osquery_result` events **with** the `important` `routing_key` value
* `zentral_login` **or** `zentral_logout` events

Boolean combinations: arrays/lists → `OR`, dictionaries/objects → `AND`.

* Within `excluded_event_filters`, the different filters are combined using the `OR` operator.
* Within each filter, the different attributes must all match (`AND`).
* For each filter attribute, at least one value must match (`OR`).

The `excluded_event_filters` **take precendence** over the `included_event_filters`. If an event is a match for the `excluded_event_filters`, the `included_event_filters` are not evaluated, and the event is excluded.

If both `excluded_event_filters` and `included_event_filters` are not set, all events will be included in the store.

### `included_event_filters`

**OPTIONAL**

A list of filters to included in the store. See `excluded_event_filters` for the filter syntax.

The `included_event_filters` are applied **after** the `excluded_event_filters`. If an event is a match for the `excluded_event_filters`, the `included_event_filters` and not evaluated, and the event is excluded.

If both `excluded_event_filters` and `included_event_filters` are not set, all events will be included in the store.

### `excluded_event_types`

**DEPRECATED**

Use `excluded_event_filters` instead.

### `included_event_types`

**DEPRECATED**

Use `included_event_filters` instead.

### `events_url_authorized_groups`

**OPTIONAL**

A list of group names. Empty by default (i.e. all users will get the links). Can be used to display the links to the events in the store to only a subset of Zentral users, if not all users have direct access to the store.

## HTTP backend options

### `endpoint_url`

**MANDATORY**

The URL where the Zentral events will be POSTed.

For example: `https://acme.service-now.com/api/now/import/zentral_events`.

### `username`

**OPTIONAL**

Username used for Basic Authentication. If used, `password` **MUST** be set too.

### `password`

**OPTIONAL**

Password used for Basic Authentication. If used, `username` **MUST** be set too.

### `headers`

**OPTIONAL**

A string / string dictionary of extra headers to be set for the HTTP requests. The `Content-Type` header is set to `application/json` by default.

**WARNING** Basic Authentication via `username` and `password` conflicts with the configuration of the `Authorization` header.

### `concurrency`

**OPTIONAL**

**WARNING** only works if the AWS SNS/SQS queues backend is used.

An integer between 1 and 20, 1 by default. The number of threads to use when posting the events. This can increase the throughput of the store worker.

### Full example

```json
{
    "backend": "zentral.core.stores.backends.http",
    "endpoint_url": "https://acme.service-now.com/api/now/import/zentral_events",
    "username": "Zentral",
    "password": "{{ env:SERVICE_NOW_API_PASSWORD }}",
    "verify_tls": true,
    "included_event_filters": [{
      "event_type": [
        "add_machine",
        "add_machine_os_version",
        "remove_machine_os_version",
        "add_machine_system_info",
        "remove_machine_system_info",
        "add_machine_business_unit",
        "remove_machine_business_unit",
        "add_machine_group",
        "remove_machine_group",
        "add_machine_disk",
        "remove_machine_disk",
        "add_machine_network_interface",
        "remove_machine_network_interface",
        "add_machine_osx_app_instance",
        "remove_machine_osx_app_instance",
        "add_machine_deb_package",
        "remove_machine_deb_package",
        "add_machine_program_instance",
        "remove_machine_program_instance",
        "add_machine_principal_user",
        "remove_machine_principal_user"
      ]
    }]
}
```

## Kinesis backend options

This store is capable of batch operation. The maximum `batch_size` is 500. See the [`kinesis:PutRecords`](https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecords.html) documentation for more details.

### AWS authentication and authorization

When operating in AWS, it is recommended to use a role attached to the EC2 instance or to the container to authenticate the calls to the Kinesis API.

Example of an IAM policy to allow Zentral to write to the Kinesis stream:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKinesisPut"
            "Action": [
                "kinesis:PutRecords",
                "kinesis:PutRecord"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:kinesis:<AWS_REGION>:<AWS_ACCOUNT_ID>:stream/<KINESIS_STREAM_NAME>",
        }
    ]
}
```

The `PutRecord` action can be omitted if the store is configured for batch operations.

If the authentication is not possible using the environment (standard environment variable, instance metadata service, …), you can set `aws_access_key_id` and `aws_secret_access_key` in the store configuration.

You can also configure an AWS IAM role to be assumed, using the `assume_role_arn` store configuration key.

### `stream`

**MANDATORY**

The name of the Kinesis stream.

### `region_name`

**MANDATORY**

The name of the Kinesis stream AWS region.

### `serialization_format`

By default, the events will be serialized using the Zentral canonical serialization.

A serialization format optimized for the use with Kinesis Firehose is also available: `firehose_v1`.

### Full example

```json
{
    "backend": "zentral.core.stores.backends.kinesis",
    "aws_access_key_id": "XXXXXXXXXXXXX",
    "aws_secret_access_key": "YYYYYYYYYYYYY",
    "assume_role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/<NAME_OF_THE_ROLE>",
    "stream": "name_of_the_stream",
    "region": "us-east-1",
    "serialization_format": "firehose_v1"
}
```

## OpenSearch backend options

Use this store if you have a managed AWS OpenSearch domain. API calls to store and retrieve the events can be authenticated using the standard AWS signatures. It is recommended to use a role attached to the EC2 instance or to the container, but an IAM key and a secret can be provided.

### `aws_auth`

**OPTIONAL**

A dictionary to configure the AWS authentication. If omitted, the API calls will not be authenticated. It must contain the AWS region in the `region` key. `access_key_id` and `secret_access_key` can also be used if the default AWS authentication via instance or container profile is not set.

### Simple example

```json
{
  "backend": "zentral.core.stores.backends.opensearch",
  "frontend": true,
  "index": "zentral-events",
  "hosts": ["https://example-00000000000000000000000000.us-east-1.es.amazonaws.com"],
  "kibana_discover_url": "https://example-00000000000000000000000000.us-east-1.es.amazonaws.com/_dashboards",
  "kibana_index_pattern_uuid": "00000000-0000-0000-0000-000000000000",
  "aws_auth": {"region": "us-east-1"}
}
```

### Full example

In this example, a separate index is setup to receive the Osquery events. You could configure it with a different [OpenSearch policy](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ism.html) to change the retention time or the storage type. Use the index name as the key, add `included_event_filters` and `excluded_event_filters`. Set a priority to make sure that only one index will be chosen by Zentral. Finally do not forget to add a default unfiltered index with the lowest priority. A `read_index` is also required in this kind of setup. It should point to an alias that is covering all the events you want to be able to retrieve in the Zentral GUI.

```json
{
  "backend": "zentral.core.stores.backends.opensearch",
  "frontend": true,
  "batch_size": 100,
  "indices": {
    "zentral-osquery": {
      "priority": 10,
      "included_event_filters": {
        "tags": ["osquery"]
      }
    },
    "zentral-other": {
      "priority": 1
    }
  },
  "read_index": "zentral-all",
  "hosts": ["https://example-00000000000000000000000000.us-east-1.es.amazonaws.com"],
  "kibana_discover_url": "https://example-00000000000000000000000000.us-east-1.es.amazonaws.com/_dashboards",
  "kibana_index_pattern_uuid": "00000000-0000-0000-0000-000000000000",
  "aws_auth": {"region": "us-east-1"}
}
```

## Panther backend options

Zentral can send events to a Panther HTTP log source, with Bearer authentication. A custom schema must be configured in Panther – use [`schema.yaml`](https://github.com/zentralopensource/zentral/tree/main/ee/zentral/core/stores/backends/panther/schema.yaml) from the Zentral repository.

### `endpoint_url`

**MANDATORY**

The Panther [HTTP Log Source](https://docs.panther.com/data-onboarding/data-transports/http) URL.

For example: `https://logs.example.runpanther.net/http/00000000-0000-0000-0000-000000000000`.

### `bearer_token`

**MANDATORY**

The token used for Bearer Authentication.

### Example

```json
{
    "backend": "zentral.core.stores.backends.panther",
    "endpoint_url": "https://logs.example.runpanther.net/http/00000000-0000-0000-0000-000000000000",
    "bearer_token": "00000000-0000-0000-0000-000000000000",
}
```

## Snowflake backend options

The Snowflake backend is read-only. It can only be used as a `frontend` backend. To store the events in snowflake, you will have to setup a pipeline using the `Kinesis` backend, and `Kinesis Firehose` for example.

### `account`

**MANDATORY**

The name of the Snowflake account

### `user`

**MANDATORY**

The name of the Snowflake user

### `password`

**MANDATORY**

The password of the Snowflake user

### `database`

**MANDATORY**

The name of the Snowflake database

### `schema`

The name of the Snowflake schema. Defaults to `PUBLIC`.

### `role`

**MANDATORY**

The name of the Snowflake role.

### `warehouse`

**MANDATORY**

The name of the Snowflake warehouse.

### `session_timeout`

In seconds, the session timeout. After the current session has timed out, a new connection will be established if necessary. Defaults to 4 hours - 10 minutes.

### Full example

```json
{
  "backend": "zentral.core.stores.backends.snowflake",
  "frontend": true,
  "username": "Zentral",
  "password": "{{ env:SNOWFLAKE_PASSWORD }}",
  "database": "ZENTRAL",
  "schema": "ZENTRAL",
  "role": "ZENTRAL",
  "warehouse": "DEFAULTWH",
  "session_timeout": 14400
}
```


## Splunk backend options

### `hec_url`

**MANDATORY**

The base URL of the Splunk HTTP Event Collector. For example: `https://splunk.example.com:8088`. The path to the collector endpoint **must not** be included.

### `hec_extra_headers`

**OPTIONAL**

A String/String dictionary of extra headers to use for the Splunk HEC requests. Empty by default. This can be used to authenticate with a proxy for example. The `Authorization` and `Content-Type` headers **cannot** be changed.

### `hec_token`

**MANDATORY**

The HEC token. It is recommended to use the common Zentral configuration options to read the value from an environment variable `"{{ env:ENV_VAR_NAME }}"`, a file `"{{ file:FILE_PATH }}"`, or a GCP or AWS secret `"{{ secret:NAME_OF_THE_SECRET }}"`.

### `hec_request_timeout`

**OPTIONAL**

In seconds. Defaults to 300s. The connection timeout for the HEC HTTP requests.

### `verify_tls`

**OPTIONAL**

A boolean value to indicate if the connection must be verified or not. Default: `true`.

### `batch_size`

**OPTIONAL**

The number of events to write in a single request. Default: `1`. A value up to `100` can be used to speed up the event storage.

### `source`

**OPTIONAL**

The name of the source to use in the Splunk events. Do not use it if the source is set by the HTTP event collector.

### `index`

**OPTIONAL**

The name of the Splunk index.

### `computer_name_as_host_sources`

**OPTIONAL**

A list of inventory source names to use to find a hostname to set as the `host` value in the Splunk event. Empty by default (i.e. the machine serial number will be used as the `host` value).

### `serial_number_field`

**OPTIONAL**

The name of the Splunk event field to use for the machine serial number. Default: `machine_serial_number`.

### `custom_host_field`

**OPTIONAL**

If set, the event metadata host field value will be copied to this event field.

### `search_app_url`

**OPTIONAL**

The URL to the Splunk search app. For example: `https://splunk.example.com/en-US/app/search/search`. Empty by default. If set, links will be displayed in the Zentral UI to allow users to see the events in Splunk.

### `search_url`

**OPTIONAL**

The base URL of the Splunk API server. For example: `https://splunk.example.com:8089`. If this is set, along with an `authentication_token`, the store can be used as a frontend store.

### `search_extra_headers`

**OPTIONAL**

A String/String dictionary of extra headers to use for the Splunk search API requests. Empty by default. This can be used to authenticate with a proxy for example. The `Authorization` and `Content-Type` headers **cannot** be changed.

### `authentication_token`

**OPTIONAL**

The authentication token to use with the Splunk API server. If this is set, along with a  `search_url`, the store can be used as a frontend store.

### `search_source`

**OPTIONAL**

If set, a `source` filter will be added to the search jobs and urls. Use this for example if a single Splunk index is used for multiple Zentral instances.

### `search_timeout`

**OPTIONAL**

In seconds. Defaults to 300s. The number of seconds to keep a search after processing has stopped. Only used if the store is configured as a frontend store.

### Full example

```json
{
    "backend": "zentral.core.stores.backends.splunk",
    "frontend": false,
    "hec_url": "https://splunk.example.com:8088",
    "hec_extra_headers": {
      "CF-Access-Client-Id": "123",
      "CF-Access-Client-Secret": "{{ env:SPLUNK_HEC_CF_ACCESS_CLIENT_SECRET }}"
    },
    "hec_token": "{{ env:HEC_TOKEN }}",
    "hec_request_timeout": 30,
    "verify_tls": true,
    "batch_size": 100,
    "source": "zentral.example.com",
    "index": "zentral",
    "computer_name_as_host_sources": ["santa", "osquery"],
    "serial_number_field": "serial_number",
    "search_app_url": "https://splunk.example.com/en-US/app/search/search",
    "search_url": "https://splunk.example.com:8089",
    "search_extra_headers": {
      "CF-Access-Client-Id": "456",
      "CF-Access-Client-Secret": "{{ env:SPLUNK_SEARCH_CF_ACCESS_CLIENT_SECRET }}"
    },
    "authentication_token": "{{ env:SPLUNK_AUTH_TOKEN }}",
    "search_source": "zentral.example.com",
    "search_timeout": 300
}
```
