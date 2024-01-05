# Configuration

## Serialization

The configuration is either a JSON object or a YAML associative array. In this document, we will use a dotted notation for the "absolute path" to a configuration key. For example `api.tls_cert` is the `tls_cert` configuration key in the `api` section. A section is a JSON object or a YAML associative array. In a JSON configuration, all sections/objects must be placed in a root object. In a YAML configuration, the sections are the keys of the root associative array.

```json
{
  "api": {
    "tls_cert": "-----BEGIN CERTIFICATE-----\nMIID…"
  }
}
```

```yaml
---
api:
  tls_cert: |-
    -----BEGIN CERTIFICATE-----
    MIID…
```

## Loading

The configuration can be loaded from a file or an environment variable. To load it from a file, the `ZENTRAL_CONF_DIR` environment variable must be set to the absolute path of the directory where the `base.json`, `base.yml` or `base.yaml` file is. The configuration can also be loaded from an environment variable. You can use the `ZENTRAL_CONF` or `B64GZIP_ZENTRAL_CONF` variables. `ZENTRAL_CONF` for the JSON or YAML serialized configuration. `B64GZIP_ZENTRAL_CONF` for the serialized configuration, gzipped and base64 encoded – in that order. This can be useful when storing the configuration in a cloud provider parameter store for example.

## Sections

 * [`api`](api/)
 * [`django`](django/)
 * `queues`
 * [`password_reset_handler`](password_reset_handler/)
 * [`stores`](stores/)
 * [`secret_engines`](secret_engines/)
 * `actions`
 * `apps`
 * `events`
 * `extra_links`
 * [`users`](users/)
