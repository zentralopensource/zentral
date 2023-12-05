# Django configuration section

Root key: `django`

In this [section](../#sections), we can configure the underlying Django application.


## Security

### `django.SECRET_KEY`

**MANDATORY**

This is the key used by Django for cryptographic signing – to verify the user sessions for example. Must be trully random and must stay secret. Unique for every Zentral deployment.
If not set here, it will be regenerated everytime the app is restarted, and this will invalidate the sessions.

### `django.SECRET_KEY_FALLBACKS`

**OPTIONAL**

`SECRET_KEY_FALLBACKS` can be used to rotate secret keys. The values will not be used to sign data, but if specified, they will be used to validate signed data and must be kept secure.

### `django.ALLOWED_HOSTS`

A list of strings representing the host/domain names that are accepted. List of the `api.fqdn` and `api.fqdn_mtls` by default. Read more about it in the [Django documentation](https://docs.djangoproject.com/en/2.2/ref/settings/#std:setting-ALLOWED_HOSTS).

### `django.DATA_UPLOAD_MAX_MEMORY_SIZE`

Default: `10485760` (10MB)

Maximum size in bytes that a request body may be.

## Email

### `django.DEFAULT_FROM_EMAIL`

Default: `webmaster@localhost`

Email address used to send emails from Zentral – password recovery emails for example.

### `django.EMAIL_*`

 * `EMAIL_BACKEND`
 * `EMAIL_HOST`
 * `EMAIL_PORT`
 * `EMAIL_HOST_USER`
 * `EMAIL_HOST_PASSWORD`
 * `EMAIL_USE_TLS`
 * `EMAIL_USE_SSL`
 * `EMAIL_TIMEOUT`
 * `EMAIL_SSL_KEYFILE`
 * `EMAIL_SSL_CERTFILE`
 * `EMAIL_FILE_PATH`

For all those configuration keys, please refer to the [Django documentation](https://docs.djangoproject.com/en/2.2/ref/settings/#email-backend).

## Authentication

### `django.AUTH_PASSWORD_VALIDATORS`

Default: `[]`

The list of validators that are used to check the strength of user’s passwords. See [Password validation](https://docs.djangoproject.com/en/2.2/topics/auth/passwords/#password-validation) for more details. By default, no validation is performed and all passwords are accepted.

### `django.SESSION_COOKIE_AGE`

Default: `1209600` (2 weeks, in seconds)

The age of session cookies, in seconds.

### `django.SESSION_EXPIRE_AT_BROWSER_CLOSE`

Default: `false`

Whether to expire the session when the user closes their browser. See [Browser-length sessions vs. persistent sessions](https://docs.djangoproject.com/en/2.2/topics/http/sessions/#browser-length-vs-persistent-sessions).

### `django.MAX_PASSWORD_AGE_DAYS`

If set, a custom middleware will be installed to enforce a password change periodically.

## Cache

### `django.CACHES`

Can be used to configure the cache used by Zentral. [Local-memory caching](https://docs.djangoproject.com/en/2.2/topics/cache/#local-memory-caching) by default. For more information, go to the [the Django documentation](https://docs.djangoproject.com/en/2.2/ref/settings/#std:setting-CACHES).

## PostgreSQL database

### `django.POSTGRES_HOST`

Default: `""`

Which host to use when connecting to the database. An empty string means localhost.

### `django.POSTGRES_PORT`

Default: `""`

The port to use when connecting to the database. An empty string means the default port.

### `django.POSTGRES_NAME`

Default: `zentral`

The name of the database to use.

### `django.POSTGRES_USER`

Default: `zentral`

The username to use when connecting to the database.

### `django.POSTGRES_PASSWORD`

Default: `""`

The password to use when connecting to the database.

## Celery

Celery is used for background tasks.

### `django.CELERY_BROKER_URL`

Default: `amqp://guest:guest@rabbitmq:5672//`

The connection string used by Celery to connect to the task management queues. The default value will make Celery connect to the rabbitmq container. For more information, please refer to the [Celery documentation](https://docs.celeryproject.org/en/stable/userguide/configuration.html#std-setting-broker_url).

### `django.CELERY_BROKER_TRANSPORT_OPTIONS`

Default: `{}` 

A dict of additional options passed to the underlying Celery transport. Please refer to the [Celery documentation](https://docs.celeryproject.org/en/stable/userguide/configuration.html#std-setting-broker_transport_options).

## File storage

### `django.STORAGES`

By default, Zentral will use the following settings:

```python
{
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage",
    },
}
```

The `default` storage backend is [`django.core.files.storage.FileSystemStorage`](https://docs.djangoproject.com/en/4.2/ref/files/storage/#django.core.files.storage.FileSystemStorage). Supported alternatives:

 * [`zentral.utils.gcs_storage.ZentralGoogleCloudStorage`](https://github.com/zentralopensource/zentral/blob/main/zentral/utils/gcs_storage.py) a subclass of [`storages.backends.gcloud.GoogleCloudStorage`](https://django-storages.readthedocs.io/en/latest/backends/gcloud.html) that enables URL signatures without extra credentials file.
 * [`storages.backends.s3boto3.S3Boto3Storages`](https://django-storages.readthedocs.io/en/latest/backends/amazon-S3.html)

The `staticfiles` storage backend is [`ManifestStaticFilesStorage`](https://docs.djangoproject.com/en/4.2/ref/contrib/staticfiles/#manifeststaticfilesstorage). The [`collectstatic`](https://docs.djangoproject.com/en/4.2/ref/contrib/staticfiles/#collectstatic) command needs to be run to collect and prepare all the files, when [`django.DEBUG`](#djangodebug) is false.

Alternatively, [whitenoise](https://whitenoise.readthedocs.io/en/latest/) can be used to serve the static files directly from the web application. This is useful when Zentral is deployed behind a load balancer without `nginx` as reverse proxy.

### `django.MEDIA_ROOT`

Default: `""`

When using the [default file storage](https://docs.djangoproject.com/en/4.2/ref/files/storage/#django.core.files.storage.FileSystemStorage), this is a path to the directory that will hold the files.

### `django.STATIC_ROOT`

Default: `/zentral_static`

The absolute path to the directory where [collectstatic](https://docs.djangoproject.com/en/4.2/ref/contrib/staticfiles/#django-admin-collectstatic) will collect static files for deployment.

## Internationalization

### `django.LANGUAGE_CODE`

Default: `en-us`

A string representing the language code for this installation. See [Internationalization and localization](https://docs.djangoproject.com/en/2.2/topics/i18n/).

## Logging

### `django.DEBUG`

Turns on/off debugging. Never turn in on in production deployments. `false` by default.

### `django.LOG_FORMATTER`

Can be used to load a different log formatter. The default one will simply output a formatted string. Available ones:

 * `zentral.utils.logging.JSONFormatter`
 * `zentral.utils.logging.DatadogJSONFormatter`

### `django.LOG_ASCTIME`

Default: `true`

Turns on/off the timestamps in the default log formatter.
