# Architecture Overview

## Introduction

### Which problem Zentral solves?
**Asset Management**: helps organizations in managing their IT assets, tracking hardware and software inventory, and monitoring device health and performance.

**Endpoint Security**: provides an all-in-one solution for endpoint security that includes continuous monitoring, vulnerability scanning, and malware detection.

**Threat Detection**: helps in identifying and responding to advanced threats, malware, and suspicious activities through its advanced threat detection features, including behavior-based analytics, network traffic analysis, and log monitoring.

**Incident Response**: provides a robust incident response system that enables teams to investigate security incidents and respond to them effectively.

**Compliance**: assists in maintaining regulatory compliance by providing automated auditing, reporting, and compliance management features.

### Which are the key benefits?
**Centralized Endpoint Management**: offers centralized management of endpoints, making it easier for organizations to monitor and manage their IT assets effectively.

**Advanced Threat Detection**: advanced threat detection features enable organizations to detect and respond to advanced threats, malware, and suspicious activities in real-time.

**Automate Incident Response**: provides a powerful incident response system that enables organizations to automate and streamline their incident response processes, reducing response times and minimizing the impact of security incidents.

**Comprehensive Compliance Management**: helps organizations stay compliant with various regulations and standards by providing automated auditing, reporting, and compliance management features.

**Open Source Platform**: is an open-source platform, which means it's highly customizable and can be extended with custom plugins and integrations.

**Low Cost of Ownership**: is free to use and provides a low cost of ownership, making it an affordable solution for organizations of all sizes.


## Architecture overview

### Key Components

![Software Architecture overview](/images/architecture/key_components.svg)

#### Description

##### Endpoint

**Agents**: supports agents that can be installed on endpoints to collect and send data to the Zentral Server for analysis and processing.

**Enrollment profile**: a configuration that enrolls devices, into an organization's endpoint management system.

**Sensors**: collect endpoint data, including hardware and software inventory, running processes, and network connections.

##### Zentral

**Zentral Server**: is the core component of the platform that manages device registration, data ingestion, and data processing.

**Workers**: to perform background tasks, such as data ingestion, event enrichment and alerting.

**Messaging**: Several messaging destinations can be configured. Slack, email, Google chat, Freshdesk and more.

##### External and Interfaces

**Inventory sources**: Puppet, Jamf, Workspace one and other means can be used to import a large collection of endpoints into Zentral.

**Data Stores**: leverages various data stores to preserve device information, events, and logs. Can also store data to external data stores and interact with POST endpoints.

**API**: enables developers to build custom integrations and extensions (e.g. Terraform) used for automation: reporting, tagging, CRUD operations.

### Modules

A module refers to a **pluggable standalone component or extension** that provides additional functionality to the platform. Some of the ones supported by Zentral are shown in the following diagram.

![Software Architecture Modules](/images/architecture/modules.svg)

### Interactions with Endpoints

#### To Zentral

Some examples of Events and Status received from Endpoints  are:

**Enrollment**: hostname, IP and other Endpoint identification.

**Heartbeat**: CPU usage, memory usage, disk space among others. 

**Security**: type of attack or event, the affected system components, and any remediation actions taken.

**Inventory**: installed applications, OS version, hardware specifications  and network configurations.

#### From Zentral

Some examples of Configurations, Assets, Activations and Managements sent to Endpoints  are:

**Configuration/Assets**: updates and changes to security policies or software.

**Security Policies**: blocking traffic from suspicious IP addresses or blocking access to certain network resources.

**Management**: variety of purposes, such as initiating a system reboot, performing a network scan, or running a diagnostic tool.


## Architecture decisions

A brief description of the Architecture decisions, Frameworks and tools used in Zentral.

**Python/Django Framework**: Zentral is built on top of the Python programming language and the Django web framework. This choice of technology provides a stable and well-supported foundation for the platform, as well as a wide range of third-party libraries and plugins that can be used to extend its functionality.

**Modular Architecture**: designed as a modular platform, with separate components for data collection, processing, and storage. This modular architecture enables developers to add new features and capabilities to the platform without disrupting the core functionality.

**Asynchronous Processing**: Zentral uses asynchronous processing techniques, such as Celery, RabbitMQ and Google PubSub to handle incoming data and alerts. This approach ensures that the platform can handle large volumes of data and respond quickly to security events.

**Storage Flexibility**: the platform supports a range of different technologies to store events, including Elasticsearch, Kinesis, Splunk, Humio, OpenSearch and Azure. This flexibility enables organizations to choose the database technology that best fits their needs and requirements.

**RESTful API**: Zentral provides a RESTful API that enables developers to build custom integrations and extensions, as well as to automate tasks and workflows within the platform (e.g. reporting).

## System performance and scalability

Cloud Based deployment (VMs or containers) can be scaled horizontally and vertically in AWS and GCP. Also Terraform configuration is provided for Enterprise plan.

Queue workers can be scaled vertically and horizontally. Event stores too.

## Security and privacy

Zentral ensures the **confidentiality**, **integrity**, and **availability** of endpoint data. Here are some of the key security and privacy features implemented:

**Secure connections**: all data transmitted between Zentral and any 3rd party is encrypted using **mTLS**.

**Encryption**: Zentral can be configured to [**encrypt some DB fields**](/configuration/secret_engines/) that are considered secrets. Secret engines supported: AWS Key Mgmt Service, Fernet backend, Google Cloud Key Mgmt.

Django provides default security characteristics (API tokens, Authentication, password hashes). For authentication, [Okta](/configuration/okta_saml/) (or any other Identity Provider) can be integrated with Zentral, hence Two-Factor-Authentication (**2FA**) is supported. Two factor (WebAuthN, TOTP) also supported natively for the local accounts.

## Development process

OWASP Secure coding practices are linked in the section [Development intro](/development/). To develop in Zentral, Open Source standard workflow (repo forking) is used, in combination of a Dokerized App for local development with TLS certificates.

Regarding Testing, local automated testing and github workflow CI is being used, with coverage analysis in Coveralls: [![Coverage Status](https://coveralls.io/repos/github/zentralopensource/zentral/badge.svg?branch=main)](https://coveralls.io/github/zentralopensource/zentral?branch=main).
Besides testing, on Github CI there are automated security checks using CodeQL.
