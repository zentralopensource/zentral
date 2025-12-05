import logging
import psycopg2.extras
from collections import defaultdict
from collections.abc import Iterator
from django.db import connection, transaction
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


def _iter_group_members_tags(email_tags: dict[str, set[int]], tag_pks: set[int]) -> Iterator[tuple[str, int, bool]]:
    for email, expected_tags in email_tags.items():
        for tag_pk in tag_pks:
            yield (email, tag_pk, tag_pk in expected_tags)


def _sync_machine_tags(
        group_member_tags: Iterator[tuple[str, int, bool]],
        event_request: EventRequest
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
    with connection.cursor() as cursor:
        results = psycopg2.extras.execute_values(
            cursor, query,
            group_member_tags,
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
    group_member_tags = _iter_group_members_tags(email_tags, tag_pks)
    return _sync_machine_tags(group_member_tags, event_request)
