# Welcome to Zentral

![Zentral](images/logo_640_160.svg)

Zentral is an open-source hub for endpoint protection.

Extensions are available for many agents, to deploy and configure them, and to collect, normalize and process the events they generate.

Connectors exist for device management solutions, to track inventory changes, and if possible, dynamically change group assignments.

Events are stored in [Elasticsearch](https://www.elastic.co/elasticsearch/). They can be forwarded to third party SIEMs.

Filters can be configured to display events, and trigger actions outside of Zentral.

## Quick start

You can deploy it on your machine with [Docker](./deployment/docker-compose).

## Supported agents

* Jamf Protect
* Munki
* Osquery
* Santa

## Inventory sources

* Jamf
* Puppet
* Workspace One
* Watchman
* Filewave

## Event stores

* [AWS Kinesis](https://aws.amazon.com/kinesis/)
* [DataDog](https://www.datadoghq.com/)
* [ClickHouse](https://www.clickhouse.com/)
* [Elasticsearch](https://www.elastic.co/products/elasticsearch)
* [OpenSearch](https://opensearch.org/)
* [Panther](https://panther.com/)
* [Snowflake](https://www.snowflake.com/en/)
* [Splunk](https://www.splunk.com/en_us/software/features-comparison-chart.html)
* [sumo logic](https://www.sumologic.com/)
* Generic HTTP POST endpoint

## Actions

* Slack
* HTTP webhooks
