# Notifier configuration section

Root key: `notifier` **OPTIONAL**

In this [section](../#sections), we can configure the redis server used to invalidate cached DB objects. This is a core component of a Zentral deployment.

### `notifier.url`

**OPTIONAL**

The redis connection URL. Defaults to `redis://redis:6379/15`.

### `notifier.username`

**OPTIONAL**

The username for the redis authentication.

### `notifier.password`

**OPTIONAL**

The password for the redis authentication.
