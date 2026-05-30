# Zentral

Zentral is a Django application for managing Apple devices. It orchestrates Apple MDM and open source agents (Munki, Osquery, Santa, …), normalises their data into a unified inventory, and ships everything as events through a pluggable event pipeline.

## Stack

- **Python 3.10** / **Django** (settings: [server/server/settings.py](server/server/settings.py))
- **PostgreSQL** for the primary database
- **Celery** for background tasks (app: [server/server/celery.py](server/server/celery.py))
- **Message broker / event queue**: RabbitMQ is the dev default so everything fits in a single docker compose setup; production uses **AWS SQS** when available, otherwise **GCP Pub/Sub**
- **Redis** for caching / locks
- **Elasticsearch / OpenSearch / ClickHouse / Kinesis / S3 (Parquet) / HTTP** as event store backends
- Frontend assets built via **webpack** ([webpack.config.js](webpack.config.js))

## Repository layout

The Django project lives in [server/](server/). It runs via [server/manage.py](server/manage.py) with `DJANGO_SETTINGS_MODULE=server.settings`.

Django apps are split across three top-level locations:

- **[server/](server/)** — server-level apps that are always present
  - [accounts/](server/accounts/) — users, groups, API tokens, user tasks
  - [base/](server/base/) — base views, templates, error pages
  - [realms/](server/realms/) — identity realms (LDAP, SAML, OpenID Connect) used for SSO/SCIM
- **[zentral/core/](zentral/core/)** — core Zentral modules, always enabled
  - [events/](zentral/core/events/) — the event base classes and pipeline
  - [stores/](zentral/core/stores/) — event stores (where events are persisted/forwarded); backends live in [zentral/core/stores/backends/](zentral/core/stores/backends/)
  - [queues/](zentral/core/queues/) — the message queue abstraction used by the event pipeline (separate from Celery)
  - [incidents/](zentral/core/incidents/), [probes/](zentral/core/probes/), [compliance_checks/](zentral/core/compliance_checks/), [secret_engines/](zentral/core/secret_engines/), [terraform/](zentral/core/terraform/)
- **[zentral/contrib/](zentral/contrib/)** — optional modules, each switched on/off in the Zentral config: `inventory`, `mdm`, `munki`, `osquery`, `santa`, `monolith`, `jamf`, `puppet`, `google_workspace`

Shared utilities are in [zentral/utils/](zentral/utils/); configuration helpers in [zentral/conf/](zentral/conf/).

### Creating a new Zentral Django app

A new app's `apps.py` should define a class that **inherits from [`ZentralAppConfig`](zentral/utils/apps.py)** rather than Django's plain `AppConfig`. That base class is where the wiring lives: on `ready()` it auto-imports the app's `events`, `incidents`, `compliance_checks`, and `provisioning` submodules, and picks up its `events/templates/` directory. Declared permissions go in the `permission_models` class attribute.

See [zentral/contrib/munki/apps.py](zentral/contrib/munki/apps.py) for a minimal example.

## The `ee/` folder

[ee/](ee/) at the project root contains code **not licensed under Apache 2** (Zentral Pro Edition License). It mirrors the structure of the rest of the project — so for instance:

- [ee/server/realms/](ee/server/realms/) extends `server/realms/`
- [ee/zentral/core/stores/](ee/zentral/core/stores/) adds extra event store backends
- [ee/zentral/contrib/intune/](ee/zentral/contrib/intune/), [ee/zentral/contrib/wsone/](ee/zentral/contrib/wsone/) are EE-only contrib modules

When adding a feature, decide deliberately whether it belongs under the Apache-licensed tree or under `ee/`. Don't move code between the two without flagging it — it's a licensing change.

## Event pipeline

Everything in Zentral is an event. Each Django app defines its events in an `events/` subpackage (e.g. [zentral/contrib/munki/events/](zentral/contrib/munki/events/), [zentral/contrib/osquery/events/](zentral/contrib/osquery/events/)). Event base classes and the pipeline machinery live in [zentral/core/events/](zentral/core/events/).

Events flow through the queue abstraction in [zentral/core/queues/](zentral/core/queues/) and end up in one or more **event stores** configured under [zentral/core/stores/](zentral/core/stores/). New event store backends go in [zentral/core/stores/backends/](zentral/core/stores/backends/) (or under [ee/zentral/core/stores/backends/](ee/zentral/core/stores/backends/) if non-Apache).

## Tests

Tests live under [tests/](tests/), organised by module (e.g. `tests/munki/`, `tests/core_stores/`, `tests/server_accounts/`). The coverage configuration in [tox.ini](tox.ini) lists every package that should be covered.

Running the full suite uses Docker Compose:

```
docker compose -f docker-compose.yml -f docker-compose.tests.yml run web tests_with_coverage
```

Individual tests can be run via `server/manage.py test tests.<module>`, but the run needs every env var in `TESTS_EXTRA_ENV` (see [docker-entrypoint.py](docker-entrypoint.py)) to be set. The headline one is `ZENTRAL_CONF_DIR=/zentral/tests/conf`, which puts the full set of contrib apps in `INSTALLED_APPS`; the others force synchronous event-store writes and disable cache-sync paths that would otherwise race with tests. **All of them are load-bearing — skipping any produces misleading failures.** The `tests`/`tests_with_coverage` entrypoint commands always run the full suite (the `tests/` path is hardcoded); to run a subset, pass the env vars explicitly:

```
docker compose -f docker-compose.yml -f docker-compose.tests.yml run --rm \
    -e ZENTRAL_CONF_DIR=/zentral/tests/conf \
    -e ZENTRAL_FORCE_ES_OS_INDEX_REFRESH=1 \
    -e ZENTRAL_POLICIES_SYNC=0 \
    -e ZENTRAL_PROBES_SYNC=0 \
    -e ZENTRAL_QUIET=1 \
    -e ZENTRAL_STORES_SYNC=0 \
    web python server/manage.py test --keepdb tests.<module>
```

`--keepdb` reuses the test database across runs and skips the (slow) migration replay — the first invocation is unchanged, subsequent ones start in seconds. If migrations are renamed/squashed or the DB ends up wedged, drop the flag for one run to rebuild from scratch.

## Docs

User-facing docs live in [docs/](docs/), built with [mkdocs](https://www.mkdocs.org/) (config: [mkdocs.yml](mkdocs.yml)). After editing anything under `docs/`, validate with:

```
mkdocs build --strict
```

`--strict` promotes warnings (broken anchors, missing image paths, missing files) to errors. Plain `mkdocs build` reports the same issues as INFO/WARNING but still writes to `build/` (note: this project sets `site_dir: build/`, not the default `site/`). `mkdocs serve` gives a live preview at http://localhost:8000.

## Style & linting

- **Line length: 119** (both [pyproject.toml](pyproject.toml) ruff config and [tox.ini](tox.ini) flake8 config)
- Ruff is configured with `select = ["E", "F"]`, `ignore = ["E741"]`
- Match the surrounding code's style — most modules are plain Django + DRF, no heavy framework abstractions

### Comments

- **Default to no comments.** Don't comment methods, classes, or anything self-explanatory — well-named identifiers already say what the code does.
- Only add a comment when it explains *why*: a corner case, a non-obvious constraint, a workaround, or something that looks simpler than it actually is and would trip up a future reader.
- Don't write docstrings or comments that just restate the signature. Don't reference tasks, PRs, or callers in comments — that context belongs in commit messages.
