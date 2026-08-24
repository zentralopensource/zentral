import codecs
import json
from django.conf import settings
from django.db import transaction
from django.db.models import F
from rest_framework import serializers
from rest_framework.exceptions import ParseError
from rest_framework.parsers import BaseParser
from zentral.core.events.base import AuditEvent
from .compliance_checks import sync_query_compliance_check
from .events import post_osquery_pack_update_events
from .models import Pack, PackQuery, Query
from .serializers import OsqueryPackSerializer


class OsqueryConfigParser(BaseParser):
    media_type = 'application/x-osquery-conf'

    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
        try:
            # https://github.com/osquery/osquery/pull/2785
            # https://github.com/osquery/osquery/issues/1689
            decoded_stream = codecs.getreader(encoding)(stream).read()
            sink = ""
            for line in decoded_stream.replace("\\\n", "").splitlines():
                line = line.strip()
                if line.startswith("#") or line.startswith("//"):
                    continue
                sink += line + "\n"
            return json.loads(sink)
        except ValueError:
            raise ParseError('Osquery config parse error')


def update_or_create_pack(request, data, slug=None, pack=None, delete_extra_queries=True):
    assert slug is not None or pack is not None
    serializer = OsqueryPackSerializer(data=data)
    serializer.is_valid(raise_exception=True)

    # (instance, action, prev_value) for each object the import changes. the events are built after
    # the commit, so that the new value they carry is the state the whole import settled on.
    audit_events = []

    if not pack:
        # create or update pack
        pack_defaults = serializer.get_pack_defaults(slug)
        if Pack.objects.exclude(slug=slug).filter(name=pack_defaults["name"]).exists():
            raise serializers.ValidationError(
                {'name': 'A pack with the same name but a different slug already exists'}
            )
        pack, pack_created = Pack.objects.get_or_create(slug=slug, defaults=pack_defaults)
    else:
        slug = pack.slug
        pack_defaults = {}
        pack_created = False
    Pack.objects.select_for_update().filter(pk=pack.pk)
    pack_update_event = {}
    if pack_created:
        pack_update_event["result"] = "created"
        audit_events.append((pack, AuditEvent.Action.CREATED, None))
    else:
        pack_prev_value = pack.serialize_for_event()
        pack_updated = False
        # the response of the standard pack endpoint carries this difference, so it is still built
        # here. the audit event of the pack carries the whole value before and after instead.
        pack_updates = {}
        for attr, new_val in pack_defaults.items():
            old_val = getattr(pack, attr)
            if old_val != new_val:
                setattr(pack, attr, new_val)
                pack_updated = True
                if old_val:
                    pack_updates.setdefault("removed", {})[attr] = old_val
                if new_val:
                    pack_updates.setdefault("added", {})[attr] = new_val
        if pack_updated:
            pack.save()
            pack_update_event["result"] = "updated"
            pack_update_event["updates"] = pack_updates
            audit_events.append((pack, AuditEvent.Action.UPDATED, pack_prev_value))
        else:
            pack_update_event["result"] = "present"

    # create update or delete pack queries
    pack_queries_created = pack_queries_deleted = pack_queries_present = pack_queries_updated = 0
    found_query_slugs = []
    for query_slug, pack_query_defaults, query_defaults in serializer.iter_query_defaults(slug):
        found_query_slugs.append(query_slug)
        compliance_check = query_defaults.pop("compliance_check")
        try:
            pack_query = pack.packquery_set.select_related("query").get(slug=query_slug)
        except PackQuery.DoesNotExist:
            # update or create query
            query_name = query_defaults.pop("name")
            query, query_created = Query.objects.get_or_create(name=query_name, defaults=query_defaults)
            query_prev_value = None
            query_updated = False
            if not query_created:
                query_prev_value = query.serialize_for_event()
                query_sql_updated = False
                for attr, new_val in query_defaults.items():
                    old_val = getattr(query, attr)
                    if old_val != new_val:
                        setattr(query, attr, new_val)
                        query_updated = True
                        if attr == "sql":
                            query_sql_updated = True
                            query.version = F("version") + 1
                if query_updated:
                    query.save()
                    if query_sql_updated:
                        query.refresh_from_db()

            # create, update or delete compliance check
            cc_created, cc_updated, cc_deleted = sync_query_compliance_check(query, compliance_check)

            if query_created:
                audit_events.append((query, AuditEvent.Action.CREATED, None))
            elif query_updated or cc_created or cc_updated or cc_deleted:
                audit_events.append((query, AuditEvent.Action.UPDATED, query_prev_value))

            # create pack query
            pack_query = PackQuery.objects.create(pack=pack, query=query, **pack_query_defaults)
            pack_queries_created += 1
            audit_events.append((pack_query, AuditEvent.Action.CREATED, None))
            continue

        # update pack query
        pack_query_prev_value = pack_query.serialize_for_event()
        pack_query_updated = False
        for attr, new_val in pack_query_defaults.items():
            old_val = getattr(pack_query, attr)
            if old_val != new_val:
                setattr(pack_query, attr, new_val)
                pack_query_updated = True
        if pack_query_updated:
            pack_query.save()

        # update query
        query = pack_query.query
        query_prev_value = query.serialize_for_event()
        query_updated = False
        query_sql_updated = False
        for attr, new_val in query_defaults.items():
            old_val = getattr(query, attr)
            if old_val != new_val:
                setattr(query, attr, new_val)
                query_updated = True
                if attr == "sql":
                    query_sql_updated = True
                    query.version = F("version") + 1
        if query_updated:
            query.save()
            if query_sql_updated:
                query.refresh_from_db()

        # create, update or delete compliance check
        cc_created, cc_updated, cc_deleted = sync_query_compliance_check(query, compliance_check)

        if query_updated or cc_created or cc_updated or cc_deleted:
            audit_events.append((query, AuditEvent.Action.UPDATED, query_prev_value))
        if pack_query_updated:
            audit_events.append((pack_query, AuditEvent.Action.UPDATED, pack_query_prev_value))

        if pack_query_updated or query_updated or cc_created or cc_updated or cc_deleted:
            pack_queries_updated += 1
        else:
            pack_queries_present += 1

    # delete extra pack queries
    if delete_extra_queries:
        for pack_query in pack.packquery_set.select_related("pack", "query").exclude(slug__in=found_query_slugs):
            pack_query_prev_value = pack_query.serialize_for_event()
            pack_query_pk = pack_query.pk
            pack_query.delete()
            pack_query.pk = pack_query_pk  # re-hydrate the primary key for the event
            audit_events.append((pack_query, AuditEvent.Action.DELETED, pack_query_prev_value))
            pack_queries_deleted += 1

    pack_update_event["query_results"] = {
        "created": pack_queries_created,
        "deleted": pack_queries_deleted,
        "present": pack_queries_present,
        "updated": pack_queries_updated
    }
    pack_update_event["pack"] = pack.serialize_for_event(keys_only=True)

    # the difference stays in the response, and comes out of the event: the audit event of the pack
    # carries the value before and after, which says more
    sync_report = {k: v for k, v in pack_update_event.items() if k != "updates"}
    transaction.on_commit(
        lambda: post_osquery_pack_update_events(request, sync_report, audit_events)
    )

    return pack_update_event
