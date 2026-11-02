# Zentral

Zentral is a Django application for managing Apple devices. It orchestrates Apple MDM and open source agents (Munki, Osquery, Santa, …), normalises their data into a unified inventory, and ships everything as events through a pluggable event pipeline.

## Stack

- **Python 3.14** / **Django** (settings: [server/server/settings.py](server/server/settings.py))
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

User-facing docs live in [docs/](docs/), which is a **Hugo** site (config: [docs/hugo.yaml](docs/hugo.yaml), pages in `docs/content/`). They are published at https://www.zentral.com/docs/zentral/: the website build clones this repository and mounts `docs/content/` and `docs/layouts/` into its own Hugo site.

Preview with `docker compose -f docker-compose.docs.yml up`, then open http://localhost:1314. After editing anything under `docs/`, run the check CI runs:

```
docker compose -f docker-compose.docs.yml run --rm docs hugo --panicOnWarning
```

Internal links carry the `.md` extension and are resolved against the page tree by a render hook, which **errors on a target it cannot resolve** — so a broken link fails the build instead of reaching the site. Raw HTML in markdown is dropped: this repository takes public pull requests and the output is served from the company website.

Because the website supplies the configuration for the published build, the Hugo version and every markup option have to match on both sides. [docs/README.md](docs/README.md) says what is pinned where.

## Manifest

[com.zentral.manifest.json](com.zentral.manifest.json) records what a deployment of this Zentral needs alongside it. A file kept in a repository cannot say which commit it is stored at, so the reader supplies the identity: [zentral-images](https://github.com/zentralpro/zentral-images) when it builds from a git checkout, and the release archive when it builds from one.

The release archive is a `git archive` of a commit, with one manifest per artifacts bucket, under `zentral/zentral/` in the buckets. ztl_admin installs it with `make_new_release --archive`, at image build and in place. [.github/workflows/release-archive.yml](.github/workflows/release-archive.yml) publishes it, for a release tag or for a build of a `security/` branch, so that a fix can be deployed before it is public. Keep these properties:

- The workflow publishes only from `zentralpro/zentral`: its jobs are skipped in any other copy of the repository. The AWS role trusts only the release tags and the `security/` branches of `zentralpro/zentral`, and only its admins can create or move these refs. Keep the workflow here, not in the private copy alone: its `main` has to stay a fast-forward of this one.
- The version is `git describe --tags --long --match 'v[0-9]*' --exclude '*-*'`, the bare tag at a release. ztl_admin computes the version of a release from git with the same flags. Change both, or neither.
- The identity names this repository, also for a private build, so a private commit has to reach `main` here with its SHA unchanged: no squash or rebase merge of it.
- An object is written once. A run that finds an object with another SHA-256 checksum stops, and a broken archive is fixed by a new version.

[.github/release/build_manifest.py](.github/release/build_manifest.py) writes the manifests with zentral-manifest, which is not on PyPI: the workflow installs it from the artifacts bucket. Its `check` job runs the tests beside the script and validates `com.zentral.manifest.json`, in `zentralpro/zentral`, on each change to them and before each release. The Django suite does not run them.

Read the file for the requirements recorded today. Upgrading a deployment means meeting each of them, for example a provider version in `required_providers` wherever the Zentral configuration is kept.

When you add or change an entry:

- Give one lower bound, and only one. `min_version` for something consumed by version, such as a Terraform provider; `min_ref` for a repository with tags; `min_commit` for one without.
- Name it with `name` and `kind` when it is not a repository, or with `repository` when it is.
- Write the whole commit, all 40 characters, for `min_commit`. Short commits are not safe: git makes them longer as a repository grows, and nothing resolves them.
- Add a `note` saying why the bound is there. It reaches customer upgrade notes, so write it for someone outside the team.
- Do not add an `identity` key. The reader supplies it.

The `check` job of the release workflow validates the file. The readers validate it too.

## Style & linting

- **Line length: 119** (both [pyproject.toml](pyproject.toml) ruff config and [tox.ini](tox.ini) flake8 config)
- Ruff is configured with `select = ["E", "F"]`, `ignore = ["E741"]`
- Match the surrounding code's style — most modules are plain Django + DRF, no heavy framework abstractions

### Comments

- **Default to no comments.** Don't comment methods, classes, or anything self-explanatory — well-named identifiers already say what the code does.
- Only add a comment when it explains *why*: a corner case, a non-obvious constraint, a workaround, or something that looks simpler than it actually is and would trip up a future reader.
- Don't write docstrings or comments that just restate the signature. Don't reference tasks, PRs, or callers in comments — that context belongs in commit messages.

## PBAC rules

A view or an endpoint that a typed PBAC action protects follows [docs/content/development/pbac-rules.md](docs/content/development/pbac-rules.md). Read it before you add or review one: it is the source of truth, and the list below only names the rules.

1. One action for each decision.
2. Each element of a response has its own decision, with the action of its own resource.
3. Decide once.
4. Decide before you validate.
5. A preview never authorizes a write.
6. A list filters its rows. It never refuses.
7. A filter treats a hidden id as an unknown id.
8. A write action includes the read of its resource.
9. A PUT carries every attribute.
10. Use a context only for what does not exist yet.
11. A typed action is never reachable through `has_perm()`.
12. Fail closed.
13. A refusal on a guessable id gives the same answer as an unknown id.
14. Log every refusal. Audit every write.
15. Test each endpoint with the same matrix.

In a review, rate a leak with the leak classes of that page. Do not report an accepted class as a defect, and do not fix one with a second decision.
