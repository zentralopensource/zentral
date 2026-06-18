# OpenAPI schema

Zentral uses [drf-spectacular](https://drf-spectacular.readthedocs.io/) to generate an [OpenAPI 3](https://www.openapis.org/) schema from its Django REST Framework views.

## Enabling the schema

The settings and URL wiring is enabled only when the [`django.OPENAPI`](../configuration/django.md#djangoopenapi) flag is `true`. It is `false` by default — do not turn it on in production deployments.

The `devmdm` docker compose stack runs with `OPENAPI: true`; the default stack does not.

The Swagger UI and ReDoc bundles are served by `drf-spectacular-sidecar`, which is listed in `requirements_dev.txt`, so the documentation UIs are only available in development images.

## Viewing the documentation

With the development server running, three endpoints are exposed:

| Path | Description |
| --- | --- |
| `/api/schema/` | The raw OpenAPI schema (YAML) |
| `/api/schema/swagger-ui/` | [Swagger UI](https://swagger.io/tools/swagger-ui/) |
| `/api/schema/redoc/` | [ReDoc](https://redocly.com/redoc) |

The Swagger UI and ReDoc assets are served locally through `drf-spectacular-sidecar` — no external CDN is used — so they load under Zentral's Content Security Policy.

## Generating the schema file

The `spectacular` management command writes the schema to a file, which is handy for diffing or feeding into external tooling:

```
python server/manage.py spectacular --file openapi-schema.yaml
```

Pass `--validate` to run the result through an OpenAPI validator, and `--fail-on-warn` to turn warnings into a non-zero exit:

```
python server/manage.py spectacular --validate --file openapi-schema.yaml
```

The `spectacular` command is only registered when `OPENAPI` is `true`, and it needs the full Zentral configuration (the contrib apps must be enabled), so run it inside the `web` container:

```
docker compose -f docker-compose.yml \
    exec web python server/manage.py spectacular --validate --file openapi-schema.yaml
```
