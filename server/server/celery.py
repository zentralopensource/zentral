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


def create_task_result_on_publish(sender=None, headers=None, body=None, **kwargs):
    if (
        not isinstance(headers, dict)
        or "id" not in headers
        or "task" not in headers
        or sender not in registered_task_names
        or not isinstance(body, tuple)
        or not len(body) == 3
        or not isinstance(body[1], dict)
    ):
        logger.error("Unexpected calling context")
        return

    # essentially transforms a single-level of the headers dictionary
    # into an object with properties
    request = type('request', (object,), headers)

    (task_args, task_kwargs, task_embed) = body

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
    else:
        if 'task_user' in task_kwargs:
            try:
                task_user_pk = task_kwargs['task_user']

                # TODO: better circular import
                from accounts.models import User, UserTask
                from django_celery_results.models import TaskResult

                UserTask.objects.create(
                    user=User.objects.get(id=task_user_pk),
                    task_result=TaskResult.objects.get(task_id=headers["id"])
                )
            except Exception:
                logger.exception(
                    "UserTask could not be created. Is the user %s or task %s result missing?",
                    task_user_pk,
                    headers["id"]
                )


before_task_publish.connect(create_task_result_on_publish, dispatch_uid='create_task_result_on_publish')
