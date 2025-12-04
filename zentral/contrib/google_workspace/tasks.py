import uuid
import logging
from celery import shared_task
from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.utils import sync_group_tag_mappings as sync


logger = logging.getLogger('zentral.contrib.google_workspace.tasks')


@shared_task
def sync_group_tag_mappings_task(connection_pk: uuid) -> dict[str, dict[str, str]]:
    try:
        connection = Connection.objects.get(pk=connection_pk)
    except Connection.DoesNotExist:
        logger.warning(f"Connection for pk {connection_pk} not found.")
        return {"connection_not_found": {"pk": str(connection_pk)}}
    count = sync(connection)
    return {
        "connection": {"pk": str(connection.pk), "name": connection.name},
        "machine_tags": count}
