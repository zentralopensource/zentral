# OpenAPI schema

Zentral uses [drf-spectacular](https://drf-spectacular.readthedocs.io/) to generate an [OpenAPI 3](https://www.openapis.org/) schema from its Django REST Framework views.

## Enabling the schema

The settings and URL wiring is enabled only when the [`django.OPENAPI`](../configuration/django.md#djangoopenapi) flag is `true` (and `DEBUG` is on). It is `false` by default — do not turn it on in production deployments.

## Viewing the API documentation

With the development server running, two endpoints are exposed:

| Path | Description |
| --- | --- |
| `/api/schema/` | The raw OpenAPI schema (YAML) |
| `/api/schema/explorer/` | OpenAPI schema explorer [Stoplight Elements](https://stoplight.io/open-source/elements) |

The explorer assets are served locally from `server/static/dist/`. They are bundled through webpack (the `elements` entry in `webpack.config.js`). Run `npm run build` to generate the assets.

## Generating the schema file

The `spectacular` management command writes the schema to a file, which is handy for diffing or feeding into external tooling:

```
python server/manage.py spectacular --file openapi-schema.yaml
```

Pass `--validate` to run the result through an OpenAPI validator, and `--fail-on-warn` to turn warnings into a non-zero exit:

```
python server/manage.py spectacular --validate --file openapi-schema.yaml
```

The `spectacular` command is only registered when `OPENAPI` is `true` (and `DEBUG` is on), and it needs the full Zentral configuration (the contrib apps must be enabled), so run it inside the `web` container:

```
docker compose -f docker-compose.yml \
    exec web python server/manage.py spectacular --validate --file openapi-schema.yaml
```


[OAD(./openapi-schema.yaml)]