import logging
import os
from celery import Celery, states
from celery.signals import before_task_publish
from django.utils.functional import SimpleLazyObject


logger = logging.getLogger("zentral.celery")


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
app = Celery('zentral')
app.conf.broker_connection_retry_on_startup = True
app.conf.result_extended = True
app.conf.task_track_started = True
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


# workaround for an issue where django-celery-results is not adding PENDING tasks to the database.
# see https://github.com/celery/django-celery-results/issues/286#issuecomment-1789094153


def get_db_result_backend():
    from django_celery_results.backends.database import DatabaseBackend
    return DatabaseBackend(app)


db_result_backend = SimpleLazyObject(get_db_result_backend)


def get_registered_task_names():
    return app.tasks.keys()


registered_task_names = SimpleLazyObject(get_registered_task_names)


def create_task_result_on_publish(sender=None, headers=None, **kwargs):
    if (
        not isinstance(headers, dict)
        or "id" not in headers
        or "task" not in headers
        or sender not in registered_task_names
    ):
        logger.error("Unexpected calling context")
        return

    # essentially transforms a single-level of the headers dictionary
    # into an object with properties
    request = type('request', (object,), headers)

    try:
        db_result_backend.store_result(
            headers["id"],
            None,
            states.PENDING,
            traceback=None,
            request=request,
        )
    except Exception:
        logger.exception("Could not store pending task %s result", headers["id"])


before_task_publish.connect(create_task_result_on_publish, dispatch_uid='create_task_result_on_publish')
