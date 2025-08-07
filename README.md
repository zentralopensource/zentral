# Welcome to Zentral
[![Tests](https://github.com/zentralopensource/zentral/actions/workflows/tests.yml/badge.svg)](https://github.com/zentralopensource/zentral/actions/workflows/tests.yml)
[![Coverage Status](https://coveralls.io/repos/github/zentralopensource/zentral/badge.svg?branch=main)](https://coveralls.io/github/zentralopensource/zentral?branch=main)
[![Documentation Status](https://readthedocs.org/projects/zentral/badge/?version=latest)](https://docs.zentral.io)
[![GitHub Release](https://img.shields.io/github/v/release/zentralopensource/zentral?include_prereleases)](https://github.com/zentralopensource/zentral/releases/)

[Zentral](https://zentral.com) is a system to manage Apple devices under high security considerations. Zentral integrates deeply with enterprise architecture, such as IdPs, SIEMs and an entity’s PKI to implement robust security measures and best practices. Zentral fully supports config-as-code and its APIs can be managed with the [Zentral Official Terraform Provider](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs).

Zentral orchestrates Apple MDM and popular open source agents that complement it. Zentral integrations work with the agents as they are - if you are familiar with them, you can apply your knowledge.

- [Apple MDM](https://docs.zentral.io/en/latest/apps/mdm) to handle automatic device enrollment and essential configuration
- [Munki](https://github.com/munki/munki) to manage software distribution and patching  
- [Osquery](https://github.com/osquery/osquery) to get data from devices  
- [Santa](https://github.com/northpolesec/santa) for binary authorization and data collection

Zentral offers Application Allowlisting with a user portal to handle authorization requests, based on user voting or admin approvals. Decisions are persistent because of stable identifiers and Zentral presents a full audit trail for permissions. Aggregates of Santa events expose shadow IT and guide building the Allowlist. Zentral's Munki integration gives you control and reporting over distribution & patching of software on the fleet. 
  
Zentral can run compliance checks against custom benchmarks. Compliance checks can be based on inventory data, scripts and queries. You can send compliance change events to other systems for conditional access via the [Shared Signals Framework](https://sharedsignals.guide).

### How to run Zentral
There are many moving parts in the Zentral platform and not all are self-explanatory. If you want to get the most out of it, we recommend the Zentral SaaS offering or supported Zentral private cloud deployments for developer pairing and guidance. We offer managed instances for PoCs and are happy to help.
  
For testing purposes (and for features not licensed under the [ZPEL-1.0](https://github.com/zentralopensource/zentral/blob/main/LICENSE)) you can use ["docker compose"](https://docs.zentral.io/en/latest/deployment/docker-compose/).

### How to learn Zentral
- Read the [Zentral docs](https://docs.zentral.io) and the [Terraform provider docs](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs)  
- Use the [Terraform Starterkit](https://github.com/zentralopensource/zentral-cloud-tf-starter-kit) as a primer for a macOS client in a repo 
- Ask away in our channel [#Zentral](https://macadmins.slack.com/archives/C0BNC1SLC) over at MacAdmins Slack
  
## Key concepts in Zentral

### Event-driven architecture
- Everything in Zentral is an event
- Events are presented with the same metadata structure and where possible, events are enriched with unified inventory data
- Events can be filtered and shipped to different stores

### Tagging & sharding
Tags can be used to scope configuration to devices across all modules in Zentral. You can tag devices based on set conditions and attributes, you can use SCIM to create tags based on IdP group membership and you can also build mass tagging automations.
  
You can use sharding to roll out configuration only to smaller subsets of machines. For example, you could use 20% shard on the tag `canary` to test a new version of a software on only a sample of devices, before releasing it to the whole canary group.   

### GitOps & config as code with Terraform
Almost every configuration item in Zentral can be managed as a [Terraform Resource](https://registry.terraform.io/providers/zentralopensource/zentral/latest/docs). You can keep a whole macOS client configured from a [repository](https://github.com/zentralopensource/zentral-cloud-tf-starter-kit), with CI/CD and peer review and you can always return to a previous "known good configuration". 
  
## Key components of Zentral
### Unified Inventory
Zentral's core capability is normalising data gathered from different [inventory sources](https://docs.zentral.io/en/latest/apps/inventory/) into a unified data schema. You can search for devices based all kinds of data that Zentral collects and you can view deeply into a devices health, events attached to it and its MDM command history for troubleshooting.

### Apple MDM
Zentral can manage Apple devices via the MDM protocol. It supports DDM and can handle anything you would expect from an MDM, like software update enforcements, FileVault key escrow and recovery passwords. You can group essential settings and profiles into [Blueprints](https://docs.zentral.io/en/latest/apps/mdm/#mdm-blueprints) and scope them to devices based on tags. 

### Munki module
[Munki](https://github.com/munki/munki) is the de facto king of patch management. Using Zentral as a sync server for Munki adds a dynamic layer for scoping: You can use [sharding](https://docs.zentral.io/en/latest/apps/monolith/#pkginfo-sharding) for progressive rollouts, and work with the tags to assign sub-manifests or catalogs based on IdP group membership for example. The events feed into detailed visualisations in Grafana. 

### Osquery module
Zentral can act as a remote server for [Osquery](https://github.com/osquery/osquery) and handle configuration management, scheduled and ad-hoc query execution, file carving, and log collection. You can use tags to scope and shards sample queries. Queries can act as compliance checks and be displayed and searched in the inventory and compliance change events can be transmitted to other systems via the [Shared Signals Framework](https://sharedsignals.guide).

### Santa module
Using Zentral as a sync server to manage [Santa](https://github.com/northpolesec/santa) rules is much more efficient and less error prone than using config profiles. Zentral collects all Santa events, to use for reports and alerts or to forward to a SIEM. Zentral builds aggregates on what software runs on devices to make informed decisions when building an Allowlist to prepare moving devices to Lockdown mode. 

### User portal
When running Santa in Lockdown mode, users may want to request exceptions for an app that has been blocked by a default-deny rule. This can happen in the form of user voting or an admin approval process, but both are initiated through the user portal. 
