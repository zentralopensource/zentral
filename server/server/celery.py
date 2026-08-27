import logging
import os
from celery import Celery, states
from celery.signals import before_task_publish, worker_process_shutdown, worker_shutdown
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

    task_user_pk = task_kwargs.get('task_user')
    if task_user_pk is not None:
        # TODO: better circular import
        from accounts.models import User, UserTask
        from django_celery_results.models import TaskResult

        try:
            user = User.objects.get(pk=task_user_pk)
        except User.DoesNotExist:
            # the cascade took the ownership row away with the user. Nobody is left to attribute
            # the task to, and nobody is left to keep it from either.
            logger.error("Task %s user %s does not exist", headers["id"], task_user_pk)
        else:
            # the task result endpoints key on this row, so a task published without it could not
            # be read by the user who asked for it. This signal runs before the message is
            # published: an error here fails the launch and leaves nothing queued.
            # A retry publishes the same task ID again, hence the get_or_create.
            UserTask.objects.get_or_create(
                task_result=TaskResult.objects.get(task_id=headers["id"]),
                defaults={"user": user},
            )


before_task_publish.connect(create_task_result_on_publish, dispatch_uid='create_task_result_on_publish')


# flush the event producer when a worker shuts down: the sender threads run in
# the process that posts events (the prefork child, or the main process for the
# solo/threads pools), so cover both shutdown signals. queues.stop() is a no-op
# when nothing was started.


def stop_event_queues(**kwargs):
    from zentral.core.queues import queues
    queues.stop()


worker_process_shutdown.connect(stop_event_queues, dispatch_uid='stop_event_queues')
worker_shutdown.connect(stop_event_queues, dispatch_uid='stop_event_queues')
