import codecs
import json
from django.conf import settings
from django.db import transaction
from django.db.models import F
from rest_framework import serializers
from rest_framework.exceptions import ParseError
from rest_framework.parsers import BaseParser
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
    else:
        pack_updated = False
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
        else:
            pack_update_event["result"] = "present"

    # create update or delete pack queries
    pack_queries_created = pack_queries_deleted = pack_queries_present = pack_queries_updated = 0
    pack_query_update_events = []
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
            if not query_created:
                query_updated = False
                query_sql_updated = False
                for attr, new_val in query_defaults.items():
                    query_updated = True
                    old_val = getattr(query, attr)
                    if old_val != new_val:
                        setattr(query, attr, new_val)
                        if attr == "sql":
                            query_sql_updated = True
                            query.version = F("version") + 1
                if query_updated:
                    query.save()
                    if query_sql_updated:
                        query.refresh_from_db()

            # create, update or delete compliance check
            sync_query_compliance_check(query, compliance_check)

            # create pack query
            pack_query = PackQuery.objects.create(pack=pack, query=query, **pack_query_defaults)
            pack_queries_created += 1
            pack_query_update_events.append({
                "pack_query": pack_query.serialize_for_event(),
                "result": "created"
            })
            continue

        # update pack query
        pack_query_updated = False
        pack_query_updates = {}
        for attr, new_val in pack_query_defaults.items():
            old_val = getattr(pack_query, attr)
            if old_val != new_val:
                if old_val:
                    pack_query_updates.setdefault("removed", {})[attr] = old_val
                if new_val:
                    pack_query_updates.setdefault("added", {})[attr] = new_val
                setattr(pack_query, attr, new_val)
                pack_query_updated = True
        if pack_query_updated:
            pack_query.save()

        # update query
        query = pack_query.query
        query_updated = False
        query_sql_updated = False
        for attr, new_val in query_defaults.items():
            old_val = getattr(query, attr)
            if old_val != new_val:
                reported_attr = attr
                if attr == "sql":
                    query_sql_updated = True
                    reported_attr = "query"
                if old_val:
                    pack_query_updates.setdefault("removed", {})[reported_attr] = old_val
                if new_val:
                    pack_query_updates.setdefault("added", {})[reported_attr] = new_val
                setattr(query, attr, new_val)
                if query_sql_updated:
                    query.version = F("version") + 1
                query_updated = True
        if query_updated:
            query.save()
            if query_sql_updated:
                query.refresh_from_db()

        # create, update or delete compliance check
        cc_created, cc_updated, cc_deleted = sync_query_compliance_check(query, compliance_check)

        if pack_query_updated or query_updated or cc_created or cc_updated or cc_deleted:
            pack_queries_updated += 1
            pack_query_update_events.append({
                "pack_query": pack_query.serialize_for_event(),
                "result": "updated",
                "updates": pack_query_updates
            })
        else:
            pack_queries_present += 1

    # delete extra pack queries
    if delete_extra_queries:
        for pack_query in pack.packquery_set.select_related("pack", "query").exclude(slug__in=found_query_slugs):
            pack_query_update_events.append({
                "pack_query": pack_query.serialize_for_event(),
                "result": "deleted"
            })
            pack_query.delete()
            pack_queries_deleted += 1

    pack_update_event["query_results"] = {
        "created": pack_queries_created,
        "deleted": pack_queries_deleted,
        "present": pack_queries_present,
        "updated": pack_queries_updated
    }

    full_pack_update_event = pack_update_event.copy()
    full_pack_update_event["pack"] = pack.serialize_for_event()

    transaction.on_commit(
        lambda: post_osquery_pack_update_events(request, full_pack_update_event, pack_query_update_events)
    )

    pack_update_event["pack"] = pack.serialize_for_event(short=True)
    return pack_update_event
