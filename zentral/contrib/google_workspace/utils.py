import logging
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from django.db import connection, transaction
import psycopg2.extras

from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.api_client import APIClient
from zentral.contrib.inventory.utils import send_machine_tag_events_with_event_request
from zentral.core.events.base import EventRequest


logger = logging.getLogger('zentral.contrib.google_workspace.utils')


def _resolve_group_members_to_tags(api_connection: Connection) -> tuple[dict[str, set[int]], set[int]]:
    api_client = APIClient.from_connection(api_connection)
    email_tags = defaultdict(set)
    tag_pks = set()
    for group_tag_mapping in api_connection.grouptagmapping_set.prefetch_related("tags").all():
        mapping_tag_pks = group_tag_mapping.tags.values_list("pk", flat=True)
        tag_pks.update(mapping_tag_pks)
        for member in api_client.iter_group_members(group_tag_mapping.group_email):
            email_tags[member["email"]].update(mapping_tag_pks)
    logger.info("Found %s managed tags for %s emails.", len(tag_pks), len(email_tags))
    return email_tags, tag_pks


def _get_current_tags(cursor: Any, tag_pks: set[int]):
    query = """
        select pu.unique_id, mt.tag_id from
        inventory_principaluser pu
        join inventory_machinesnapshot ms on (ms.principal_user_id = pu.id)
        join inventory_machinetag mt on (ms.serial_number = mt.serial_number)
        where exists (
          select * from inventory_currentmachinesnapshot
          where machine_snapshot_id = ms.id
        ) and mt.tag_id in %s
        group by pu.unique_id, mt.tag_id
    """
    cursor.execute(query, [tuple(tag_pks)])
    current_tags = set()
    for email, tag_pk in cursor.fetchall():
        current_tags.add((email, tag_pk))
    return current_tags


def _iter_group_members_tag_operations(
    email_tags: dict[str, set[int]],
    tag_pks: set[int],
    current_tags: set[(str, int)],
) -> Iterator[tuple[str, int, bool]]:
    for email, expected_tag_pks in email_tags.items():
        for tag_pk in tag_pks:
            tag_key = (email, tag_pk)
            tag_present = tag_key in current_tags
            tag_to_add = tag_pk in expected_tag_pks
            if tag_to_add:
                if tag_present:
                    current_tags.remove(tag_key)
                else:
                    # add the tag
                    yield (email, tag_pk, True)
            elif tag_present:
                # remove the tag
                current_tags.remove(tag_key)
                yield (email, tag_pk, False)
    # remove the other tags
    for email, tag_pk in current_tags:
        yield (email, tag_pk, False)


def _sync_machine_tags(
    email_tags: dict[str, set[int]],
    tag_pks: set[int],
    event_request: EventRequest,
) -> dict[str, int]:
    query = """
        with given_values as (
             select email, tag_id, add_operation from (values %s) as v(email, tag_id, add_operation)),
        serial_numbers as (
            select ms.serial_number, v.email, v.tag_id, v.add_operation from
                inventory_machinesnapshot ms
                join inventory_currentmachinesnapshot cms on (cms.machine_snapshot_id = ms.id)
                join inventory_principaluser pu on (pu.id = ms.principal_user_id)
                join given_values v on v.email = pu.unique_id
            group by ms.serial_number, v.email, v.tag_id, v.add_operation),
        inserted_tags as (
            insert into inventory_machinetag(serial_number, tag_id)
                select sn.serial_number, sn.tag_id
                from serial_numbers sn
                where sn.add_operation
            on conflict do nothing
            returning serial_number, tag_id, 'added'::text as action),
        deleted_tags as (
            delete from inventory_machinetag im
            using serial_numbers sn
            where not sn.add_operation
                and im.serial_number = sn.serial_number
                and im.tag_id = sn.tag_id
            returning im.serial_number, im.tag_id, 'removed'::text as action),
        results as (
            select
                it.serial_number, 'added' action, it.tag_id pk
            from
                inserted_tags it
            union
            select
                dt.serial_number, 'removed' action, dt.tag_id pk
            from
                deleted_tags dt
        )
        select
            r.serial_number, r.action, r.pk, t.name, tx.id taxonomy_pk, tx.name taxonomy_name
        from
            results r
            join inventory_tag t on (r.pk = t.id)
            left join inventory_taxonomy tx on (t.taxonomy_id = tx.id)"""

    with transaction.atomic():
        with connection.cursor() as cursor:
            current_tags = _get_current_tags(cursor, tag_pks)
            tag_ops_iterator = _iter_group_members_tag_operations(email_tags, tag_pks, current_tags)
            results = psycopg2.extras.execute_values(
                cursor, query,
                tag_ops_iterator,
                page_size=1000,
                fetch=True
            )

    def send_machine_tag_added_events():
        send_machine_tag_events_with_event_request(results, event_request)

    transaction.on_commit(send_machine_tag_added_events)

    result_count = {
        "added": 0,
        "removed": 0
    }
    for _, action, _, _, _, _ in results:
        match action:
            case "added":
                result_count["added"] += 1
            case "removed":
                result_count["removed"] += 1

    logger.info("Added %i machine tags, removed %i machine tags.", result_count["added"], result_count["removed"])

    return result_count


def sync_group_tag_mappings(api_connection: Connection, event_request: EventRequest = None) -> None:
    email_tags, tag_pks = _resolve_group_members_to_tags(api_connection)
    return _sync_machine_tags(email_tags, tag_pks, event_request)
