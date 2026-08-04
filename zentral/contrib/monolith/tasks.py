import logging

from celery import shared_task
from django.db import connection, transaction

from base.notifier import notifier

from .models import Repository
from .repository_backends import load_repository_backend


logger = logging.getLogger("zentral.contrib.monolith.tasks")


# must not collide with the other advisory lock IDs, see zentral.contrib.mdm.dep
SYNC_REPOSITORY_LOCK_ID = 24681012


def try_lock_repository_sync(repository_pk):
    # transaction scoped: released on commit, on rollback, and if the connection dies
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_xact_lock(%s, %s)",
                       [SYNC_REPOSITORY_LOCK_ID, repository_pk])
        return cursor.fetchone()[0]


@shared_task
def sync_repository_task(repository_pk, serialized_event_request=None, **kwargs):
    # kwargs absorbs task_user, added by the API view for the UserTask created in the celery signal
    db_repository = Repository.objects.get(pk=repository_pk)
    result = {"repository": db_repository.serialize_for_event(keys_only=True)}
    repository = load_repository_backend(db_repository)
    with transaction.atomic():
        if not try_lock_repository_sync(db_repository.pk):
            logger.warning("Repository %s is already being synced", db_repository.pk)
            result["status"] = "SKIPPED"
            return result
        result["operations"] = repository.sync_catalogs(serialized_event_request)
    notifier.send_notification("monolith.repository", str(db_repository.pk))
    result["status"] = "SUCCESS"
    return result
