import uuid
from django.db import connection, transaction
from django.db.models.query import QuerySet
from django.utils.text import slugify
import psycopg2.extras
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.core.events.base import EventMetadata, EventRequest


__all__ = [
    "add_machine_tags",
    "remove_machine_tags",
    "send_machine_tag_events",
    "set_machine_taxonomy_tags",
]


def fetch_tags_if_required(tags):
    if isinstance(tags, QuerySet):
        tags = list(tags)
    return tags


def send_machine_tag_events(results, request=None):
    if not results:
        return
    event_request = None
    if request:
        event_request = EventRequest.build_from_request(request)
    event_uuid = uuid.uuid4()
    event_index = 0
    for serial_number, action, pk, name, taxonomy_pk, taxonomy_name in results:
        if not isinstance(action, MachineTagEvent.Action):
            action = MachineTagEvent.Action(action)
        payload = {
            "action": action.value,
            "tag": {"pk": pk, "name": name}
        }
        if taxonomy_pk:
            payload["taxonomy"] = {"pk": taxonomy_pk, "name": taxonomy_name}
        event = MachineTagEvent(
            EventMetadata(
                uuid=event_uuid,
                index=event_index,
                machine_serial_number=serial_number,
                request=event_request,
            ),
            payload,
        )
        event.post()
        event_index += 1


def add_machine_tags(serial_number, tags, request=None):
    tags = fetch_tags_if_required(tags)
    if not tags:
        return 0
    query = (
        "with inserted_tags as ("
        "  insert into inventory_machinetag(serial_number, tag_id)"
        "  values %s"
        "  on conflict do nothing"
        "  returning serial_number, tag_id"
        ") select it.serial_number, 'added' action, t.id pk, t.name, tx.id taxonomy_pk, tx.name taxonomy_name "
        "from inserted_tags it "
        "join inventory_tag t on (it.tag_id = t.id) "
        "left join inventory_taxonomy tx on (t.taxonomy_id = tx.id)"
    )
    with connection.cursor() as cursor:
        results = psycopg2.extras.execute_values(
            cursor, query,
            ((serial_number, tag.pk) for tag in tags),
            fetch=True
        )

    def send_machine_tag_added_events():
        send_machine_tag_events(results, request)

    transaction.on_commit(send_machine_tag_added_events)
    return len(results)


def remove_machine_tags(serial_number, tags, request=None):
    tags = fetch_tags_if_required(tags)
    if not tags:
        return 0
    query = (
        "with deleted_tags as ("
        "  delete from inventory_machinetag"
        "  where serial_number = %(serial_number)s"
        "  and tag_id in %(tag_pks)s"
        "  returning serial_number, tag_id"
        ") select dt.serial_number, 'removed' action, t.id pk, t.name, tx.id taxonomy_pk, tx.name taxonomy_name "
        "from deleted_tags dt "
        "join inventory_tag t on (dt.tag_id = t.id) "
        "left join inventory_taxonomy tx on (t.taxonomy_id = tx.id)"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, {"serial_number": serial_number, "tag_pks": tuple(t.pk for t in tags)})
        results = cursor.fetchall()

    def send_machine_tag_removed_events():
        send_machine_tag_events(results, request)

    transaction.on_commit(send_machine_tag_removed_events)
    return len(results)


def set_machine_taxonomy_tags(serial_number, taxonomy, tag_names, request=None):
    query = (
        "with taxonomy_tags(name, slug, color) as ("
        "  values %%s"
        "), existing_tags as ("
        "  select it.id, it.name, it.taxonomy_id"
        "  from inventory_tag it"
        "  join taxonomy_tags tt on (it.name = tt.name)"
        "  where it.taxonomy_id = %(taxonomy_pk)s"
        "), created_tags as ("
        "  insert into inventory_tag(taxonomy_id, name, slug, color)"
        "  select %(taxonomy_pk)s, name, slug, color"
        "  from taxonomy_tags"
        "  on conflict do nothing"
        "  returning id, name, taxonomy_id"
        "), tags as ("
        "  select id, name, taxonomy_id from existing_tags"
        "  union"
        "  select id, name, taxonomy_id from created_tags"
        "), inserted_machinetags as ("
        "  insert into inventory_machinetag(serial_number, tag_id)"
        "  select %(serial_number)s, id"
        "  from tags"
        "  on conflict do nothing"
        "  returning serial_number, tag_id, 'added' action"
        "), deleted_machinetags as ("
        "  delete from inventory_machinetag"
        "  where id in ("
        "    select mt.id from inventory_machinetag mt"
        "    join inventory_tag t on (mt.tag_id = t.id)"
        "    where mt.serial_number = %(serial_number)s"
        "    and t.taxonomy_id = %(taxonomy_pk)s"
        "    and t.id not in (select id from tags)"
        "  )"
        "  returning serial_number, tag_id, 'removed' action"
        ") select imt.serial_number, imt.action, imt.tag_id pk, t.name"
        "  from inserted_machinetags imt"
        "  join tags t on (imt.tag_id = t.id)"
        "  union"
        "  select dmt.serial_number, dmt.action, dmt.tag_id pk, t.name"
        "  from deleted_machinetags dmt"
        "  join inventory_tag t on (dmt.tag_id = t.id)"
    )
    with connection.cursor() as cursor:
        # substitute the common arguments
        query = cursor.mogrify(
            query,
            {"serial_number": serial_number,
             "taxonomy_pk": taxonomy.pk},
        )
        results = psycopg2.extras.execute_values(
            cursor, query,
            ((name, slugify(name), "0079bf")  # TODO: hard-coded color
             for name in tag_names),
            fetch=True
        )

    def send_machine_tag_updated_events():
        send_machine_tag_events(
            [(serial_number, action, tag_id, tag_name, taxonomy.pk, taxonomy.name)
             for (serial_number, action, tag_id, tag_name) in results],
            request
        )

    transaction.on_commit(send_machine_tag_updated_events)
