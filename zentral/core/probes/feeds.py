from collections import OrderedDict
from importlib import import_module
import json
import logging
import pprint
from urllib.parse import urlparse
from django.utils import timezone
import requests
from rest_framework import serializers
from zentral.conf import settings
from zentral.utils.dict import dict_diff
from . import probe_classes
from .models import Feed, FeedProbe

logger = logging.getLogger("zentral.core.probes.feeds")


class FeedError(Exception):
    def __init__(self, message="Feed error"):
        self.message = message


class FeedProbeSerializer(serializers.Serializer):
    model = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField(default="")
    body = serializers.JSONField()


class FeedSerializer(serializers.Serializer):
    name = serializers.CharField()
    description = serializers.CharField(default="")
    id = serializers.RegexField(r'^([-\w]+\.)*[-\w]+\Z')
    probes = serializers.DictField(
        child=FeedProbeSerializer()
    )

    def get_name(self, url):
        return self.validated_data["name"]

    def iter_feed_probes(self):
        feed_id = self.validated_data["id"]
        for probe_id, probe_validated_data in self.validated_data["probes"].items():
            model = probe_validated_data["model"]
            probe_class = probe_classes.get(model)
            if not probe_class:
                raise FeedError("Probe {}: unknown model {}".format(probe_id, model))
            probe_serializer = probe_class.serializer_class(data=probe_validated_data["body"])
            if not probe_serializer.is_valid():
                raise FeedError("Probe {}: invalid {} body".format(probe_id, model))
            yield "{}.{}".format(feed_id, probe_id), probe_validated_data


feed_serializers = []


def get_feed_serializer_classes():
    if not feed_serializers:
        for app in settings['apps']:
            try:
                feeds_module = import_module("{}.feeds".format(app))
            except ImportError:
                pass
            else:
                feed_serializers.extend(o for o in feeds_module.__dict__.values()
                                        if hasattr(o, "get_name") and hasattr(o, "iter_feed_probes"))
    yield from feed_serializers


def get_feed_serializer(url):
    try:
        r = requests.get(url, stream=True)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise FeedError("Connection error")
    except requests.exceptions.HTTPError as e:
        raise FeedError("HTTP error {}".format(e.response.status_code))
    # TODO next line to fix import of osquery packs
    try:
        feed_data = json.loads(r.text.replace("\\\n", " "))
    except ValueError:
        raise FeedError("Invalid JSON")
    for feed_serializer_cls in get_feed_serializer_classes():
        feed_serializer = feed_serializer_cls(data=feed_data)
        if feed_serializer.is_valid():
            return feed_serializer
        else:
            logger.warning("Feed serializer %s errors", feed_serializer_cls)
            logger.warning(pprint.pformat(feed_serializer.errors))
    raise FeedError("Unknown feed type")


def update_or_create_feed(url):
    feed_serializer = get_feed_serializer(url)
    return Feed.objects.update_or_create(url=url, defaults={"name": feed_serializer.get_name(url)})


def sync_feed(feed):
    now = timezone.now()
    # feed
    feed_updated = False
    feed_serializer = get_feed_serializer(feed.url)
    current_feed_name = feed_serializer.get_name(feed.url)
    if not feed.name == current_feed_name:
        feed_updated = True
        feed.name = current_feed_name
    current_feed_description = feed_serializer.validated_data.get("description") or ""
    if not feed.description == current_feed_description:
        feed_updated = True
        feed.description = current_feed_description
    # feed probes
    seen_keys = []
    created = updated = archived = removed = 0
    # created / updated
    feed_probes = list(feed_serializer.iter_feed_probes())  # too trigger the FeedErrors before touching the DB
    for feed_probe_key, feed_probe_data in feed_probes:
        seen_keys.append(feed_probe_key)
        feed_probe, fp_created = FeedProbe.objects.get_or_create(feed=feed, key=feed_probe_key,
                                                                 defaults=feed_probe_data)
        if not fp_created:
            if feed_probe.model != feed_probe_data["model"]:
                raise FeedError("Can't change feed probe {} model.".format(feed_probe_key))
            feed_probe_data["archived_at"] = None
            diff = dict_diff({"model": feed_probe.model,
                              "name": feed_probe.name,
                              "description": feed_probe.description,
                              "body": feed_probe.body,
                              "archived_at": feed_probe.archived_at},
                             feed_probe_data)
            if diff:
                for key, val in feed_probe_data.items():
                    setattr(feed_probe, key, val)
                feed_probe.save()
                # mark all imported probe for update review
                for probe_source in feed_probe.probesource_set.all():
                    if probe_source.update_diff():
                        if not probe_source.feed_probe_update_available:
                            probe_source.feed_probe_update_available = True
                            probe_source.save()
                    elif probe_source.feed_probe_update_available:
                        probe_source.feed_probe_update_available = False
                        probe_source.save()
                updated += 1
        else:
            created += 1
    # feed_probes not in feed
    feed_probe_not_in_feed_qs = feed.feedprobe_set.exclude(key__in=seen_keys)
    # archive stale feed probes linked to probe_sources
    for feed_probe in feed_probe_not_in_feed_qs.filter(probesource__isnull=False,
                                                       archived_at__isnull=True):
        feed_probe.archived_at = now
        feed_probe.save()
        archived += 1
    # remove stale feed probes not linked to any probe_source
    for feed_probe in feed_probe_not_in_feed_qs.filter(probesource__isnull=True):
        feed_probe.delete()
        removed += 1
    operations = OrderedDict((l, v)
                             for l, v in (("created", created),
                                          ("updated", updated),
                                          ("archived", archived),
                                          ("removed", removed))
                             if v)
    feed.last_synced_at = now
    if feed_updated or operations:
        feed.updated_at = now
    feed.save()
    return operations


def export_feed(feed_name, probes, feed_description=None):
    o = urlparse(settings["api"]["tls_hostname"])
    netloc = o.netloc.split(":")[0].split(".")
    feed_id = ".".join(netloc[::-1])
    feed = {"name": feed_name,
            "id": feed_id,
            "probes": {}}
    if feed_description:
        feed["description"] = feed_description
    for probe in probes:
        probe_d = probe.export()
        if probe_d:
            feed["probes"][probe.slug] = probe_d
    return json.dumps(feed, indent=2, sort_keys=True)
