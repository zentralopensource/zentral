# Welcome to Zentral

![Zentral](images/logo_640_160.svg)

Zentral is an open-source hub for endpoint protection.

Extensions are available for many agents, to deploy and configure them, and to collect, normalize and process the events they generate.

Connectors exist for device management solutions, to track inventory changes, and if possible, dynamically change group assignments.

Events are stored in [Elasticsearch](https://www.elastic.co/elasticsearch/). They can be forwarded to third party SIEMs.

Filters can be configured to display events, and trigger actions outside of Zentral.

## Quick start

You can deploy it on your machine with [Docker](./deployment/docker-compose), or start a cloud instance from our custome _Zentral all in one_ images on [AWS](./deployment/zaio-aws) or [Google Cloud Platform](./deployment/zaio-gcp).

## Supported agents

* Filebeat
* Jamf Protect
* Munki
* Osquery
* Santa

## Inventory sources

* Filewave
* Jamf
* Puppet
* Watchman

## Event stores

* [Elasticsearch](https://www.elastic.co/products/elasticsearch)
* Kinesis
* [Azure log analytics](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-portal)
* [Splunk](https://www.splunk.com/en_us/software/features-comparison-chart.html)
* Generic HTTP POST endpoint

## Actions

* Inventory group change (for compatible inventory sources)
* Messaging (email, SMS, Slack, …)
* Tagging
* Tickets (Zendesk, Github, …)
