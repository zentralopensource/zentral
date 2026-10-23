# Zentral threat model

This file is for the Anthropic OSS Scanner. It tells the scanner what to examine, how to rate a finding, and
what a report must contain.

## What Zentral does

Zentral is a Django server that manages fleets of Apple devices. It is an MDM server for Apple devices. It
also configures and receives data from open-source agents on macOS: Santa, osquery, Munki, and the Zentral
agents (Turbo). The server keeps an inventory of the devices. It sends all its data as events through a queue
to event stores.

A user of the web interface or of the API with the necessary permissions can change what the managed devices
run and permit: configuration profiles, declarations, MDM commands, packages, scripts, osquery queries and
Santa rules. Thus, a vulnerability in Zentral can give an attacker code execution on all the managed devices.

One Zentral instance serves one organization. Organizations deploy it themselves, or use the Zentral SaaS.

## Where untrusted input enters

### Devices: `/public/<app>/`

These endpoints are on the Internet. Treat all their input as hostile.

- `/public/mdm/`: enrollment (over the air, Automated Device Enrollment, user enrollment), check-in and
  command responses (`checkin/`, `connect/`), ACME and SCEP credentials, profile, package and data asset
  downloads.
- `/public/santa/`: the Santa sync protocol.
- `/public/osquery/`: enroll, config, log, distributed queries, file carving.
- `/public/munki/` and `/public/monolith/`: Munki enrollment, scripts results, and the Munki repository.
- `/public/turbo/`: the Zentral agents (enrollment, configuration, results, inventory, uploads).

When the configuration of an app sets `mount_legacy_public_endpoints` to true, the same endpoints are also at
`/<app>/`, without the `/public/` prefix.

Each agent enrolls with an enrollment secret. The enrollment secret is in the enrollment package or profile, so
**all users of a managed device can get it**. After the enrollment, a device authenticates with a token, with
the enrollment secret, or with a client certificate.

The most important attacker is a person who controls one managed device, or who has an enrollment secret.
This person must not be able to change the data of another device, or to get its secrets, or to act as
another device.

### Identity providers and provisioning: `/public/realms/`

SAML, OpenID Connect and LDAP logins, and SCIM provisioning. The responses of an identity provider are
untrusted until Zentral verifies them.

### Webhooks

These endpoints are also on the Internet, but they do not have the `/public/` prefix. Each endpoint
authenticates the caller with the secret of an instance of a third-party service.

- `/jamf/post_event/<secret>/`: Jamf events. The secret is in the URL.
- `/wsone/instances/<pk>/event_notifications/`: Workspace ONE event notifications, with HTTP basic
  authentication.
- `/puppet/instances/<pk>/post_report/`: Puppet reports, with a token in the `Authorization` header.

A caller without the secret is a hostile Internet client.

### Third-party services

The payloads of the webhooks after the authentication. Responses from the Apple services (Apple Business
Manager, Apps and Books, APNs), Jamf, Workspace ONE, Intune, Google Workspace and PuppetDB. Treat these as
untrusted data, but not as an attacker that controls the server.

### Users and API tokens

The web interface uses Django sessions. The API (`/api/`) uses API tokens of users and of service accounts.
Permissions come from roles (Django groups) and from Cedar policies (`server/pbac/`). A user with a limited role
is a possible attacker.

### Event pipeline

Workers (`manage.py runworkers`) read the events of the devices from the queue and process them. The event
payloads are device input. Treat them as hostile.

## Deployment assumptions

- A TLS proxy (nginx or a cloud load balancer) is in front of Django. On the mTLS host name, the proxy verifies
  the client certificate and sets the `X-SSL-Client-S-DN` and `X-SSL-Client-Cert` headers. The proxy removes
  these headers when a client sends them. Clients cannot connect to Django directly.
- `DEBUG` is false in production.
- Only the operators of the instance have access to the configuration, the database, the queue and the
  secrets.

## Components that matter most

1. The `/public/` endpoints, the webhooks, and the code that they call.
2. Authentication and authorization: `server/accounts/`, `server/realms/`, `ee/server/realms/`,
   `server/pbac/`, and the permission checks in the views and in the API.
3. The secrets that Zentral keeps: FileVault personal recovery keys, recovery lock and firmware passwords,
   bootstrap tokens, push certificate and SCEP private keys, enrollment secrets, realm and event store
   credentials. See `zentral/core/secret_engines/`.
4. The data from the devices that the web interface shows (inventory, events, Santa targets, osquery results).

`ee/` holds code under the Zentral Pro Edition License. It is in scope.

## How to exercise it

- `zentral-tests tests.<module>` runs the tests of one module, for example `zentral-tests tests.santa`.
  `zentral-tests` without arguments runs all the tests. The script is `.oss-scanner/zentral-tests`. It starts
  PostgreSQL, Redis, RabbitMQ, ClickHouse and Elasticsearch first, and sets the same environment as the tests
  in CI.
- The image has a test database with all the migrations. `zentral-tests` keeps it between runs (`--keepdb`),
  and applies new migrations to it.
- The tests show how to make a valid request to each device endpoint. Use the helpers in `tests/mdm/utils.py`,
  `tests/santa/utils.py`, `tests/osquery/utils.py` and `tests/zentral_test_utils/`.

## How we rate severity

Rate the effect that you show in the proof of concept. Do not increase the severity for an attack chain that
you do not show.

**Critical**

- Remote code execution on the Zentral server or on the workers.
- An attacker without credentials, or with only an enrollment secret, makes managed devices run code or
  changes their security configuration (profiles, declarations, MDM commands, packages, scripts, osquery
  queries, Santa rules).
- An authentication bypass that gives a session or an API token with write permissions.
- An attacker without credentials reads the secrets in "Components that matter most", item 3.

**High**

- A user or an API token gets a permission that its roles do not give, or reads the secrets in item 3.
- A device, or a holder of an enrollment secret, acts as another device, or reads or changes the data of
  another device (MDM commands, inventory, secrets, Santa rules, osquery results).
- Stored XSS with a payload from a device, that runs in the browser of a user.
- A flaw in the SAML, OpenID Connect, LDAP or SCIM code that lets an attacker log in as another user, or
  change the roles of a user.
- SQL injection, or SSRF to internal addresses, from any user or device.

**Medium**

- Stored XSS with a payload from a user.
- Reflected XSS. CSRF on a view that changes data.
- One request from a device or without credentials that uses a large quantity of CPU, memory or disk on the
  server. One event that stops a worker of the event pipeline.
- A user reads inventory data that its roles do not give.

**Low**

- A finding that needs a superuser, or access to the server, the database, the queue or the configuration.
- Disclosure of version numbers, or of data that the attacker already has.
- Timing differences without a practical attack. Missing rate limits.

## Out of scope

- `conf/start/`, `docker-compose*.yml`, `tests/`, `docs/` and `.devcontainer/`. They are development and test
  configurations, with fixed secrets and `DEBUG` set to true.
- Vulnerabilities in third-party packages, and in the tools that the image builds (xar, bomutils). Report a
  finding only if the Zentral code uses them in an unsafe way.
- A feature that works as designed for a user with the necessary permission. For example, a user with the
  permission to change a script can run code on the managed devices.
- A client that sends `X-SSL-Client-S-DN` or `X-SSL-Client-Cert` directly to Django. See "Deployment
  assumptions".
- HTTP security headers that the proxy sets.
- A denial of service that needs a large number of requests.

## Reports and patches

Give each report:

- A title, and the severity from the rules above, with one sentence that explains it.
- The entry point: the URL or the worker, and what the attacker must have (nothing, an enrollment secret, an
  enrolled device, a user with a given permission).
- The file and the line of the root cause.
- A proof of concept as a Django test case in `tests/<module>/`. The test fails before the patch and passes
  after it.
- A minimal patch, with the test. Use the style of the code around it. The maximum line length is 119
  characters (`flake8`). Do not add comments that only repeat the code.

Make one report for each root cause. If one shared function or mixin causes the same flaw in many views, make
one report, and give the list of the views.
