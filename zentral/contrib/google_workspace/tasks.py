import uuid
import logging
from celery import shared_task
from zentral.contrib.google_workspace.models import Connection
from zentral.core.events.base import EventRequest
from zentral.contrib.google_workspace.utils import sync_group_tag_mappings as sync


logger = logging.getLogger('zentral.contrib.google_workspace.tasks')


@shared_task
def sync_group_tag_mappings_task(
        connection_pk: uuid,
        serialized_event_request: str = None
        ) -> dict[str, dict[str, str]]:
    try:
        connection = Connection.objects.get(pk=connection_pk)
    except Connection.DoesNotExist:
        logger.warning(f"Connection for pk {connection_pk} not found.")
        return {"connection_not_found": {"pk": str(connection_pk)}}
    event_request = None
    if serialized_event_request:
        event_request = EventRequest.deserialize(serialized_event_request)
    count = sync(connection, event_request)
    return {
        "connection": {"pk": str(connection.pk), "name": connection.name},
        "machine_tags": count}
