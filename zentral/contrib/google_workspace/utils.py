import logging
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


def _iter_group_members_tags(email_tags: dict[str, set[int]], tag_pks: set[int]) -> Iterator[tuple[str | None, int]]:
    seen_tag_pks = set()
    for email, expected_tag_pks in email_tags.items():
        seen_tag_pks.update(expected_tag_pks)
        for tag_pk in expected_tag_pks:
            yield (email, tag_pk)
    for tag_pk in tag_pks - seen_tag_pks:
        # the tag is managed, but no matching member was found.
        # still included in the data to delete orphan tags.
        yield (None, tag_pk)


def _sync_machine_tags(
        group_member_tags: Iterator[tuple[str | None, int]],
        event_request: EventRequest
) -> dict[str, int]:
    # The deleted_tags CTE removes any managed-tag row that is not in the
    # machine_managed_tags set. That set must be derived from the *complete*
    # member list, so the query has to run as a single statement: chunking the
    # input (e.g. via psycopg2.extras.execute_values page_size) would make each
    # chunk delete the tags belonging to the other chunks.
    emails: list[str | None] = []
    tag_ids: list[int] = []
    for email, tag_id in group_member_tags:
        emails.append(email)
        tag_ids.append(tag_id)
    query = """
        with given_values as (
             select * from unnest(%(emails)s::text[], %(tag_ids)s::int[]) as v(email, tag_id)),
        machine_managed_tags as (
            select ms.serial_number, v.tag_id from
                inventory_machinesnapshot ms
                join inventory_currentmachinesnapshot cms on (cms.machine_snapshot_id = ms.id)
                join inventory_principaluser pu on (pu.id = ms.principal_user_id)
                join given_values v on v.email = pu.unique_id
                where v.email is not null
            group by ms.serial_number, v.tag_id),
        inserted_tags as (
            insert into inventory_machinetag(serial_number, tag_id)
                select serial_number, tag_id
                from machine_managed_tags
            on conflict do nothing
            returning serial_number, tag_id, 'added'::text as action),
        deleted_tags as (
            delete from inventory_machinetag mt
            where exists (
              -- tag is managed
              select * from given_values
              where tag_id = mt.tag_id
            )
            and not exists (
              -- tag is not set for the machine
              select * from machine_managed_tags
              where serial_number = mt.serial_number
              and tag_id = mt.tag_id
            )
            returning mt.serial_number, mt.tag_id, 'removed'::text as action),
        results as (
            select * from inserted_tags
            union
            select * from deleted_tags
        )
        select
            r.serial_number, r.action, t.id, t.name, tx.id taxonomy_pk, tx.name taxonomy_name
        from
            results r
            join inventory_tag t on (r.tag_id = t.id)
            left join inventory_taxonomy tx on (t.taxonomy_id = tx.id)"""

    with connection.cursor() as cursor:
        cursor.execute(query, {"emails": emails, "tag_ids": tag_ids})
        results = cursor.fetchall()

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
