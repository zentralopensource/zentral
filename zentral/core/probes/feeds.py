from importlib import import_module
import json
import logging
import pprint
from urllib.parse import urlparse
from django.utils import timezone
import requests
from rest_framework import serializers
from zentral.conf import settings
from .models import Feed, FeedProbe

logger = logging.getLogger("zentral.core.probes.feeds")


class FeedError(Exception):
    def __init__(self, message="Feed error"):
        self.message = message


class FeedProbeSerializer(serializers.Serializer):
    model = serializers.CharField()
    name = serializers.RegexField(r'^[-\w]+\Z')
    body = serializers.JSONField()


class FeedSerializer(serializers.Serializer):
    name = serializers.CharField()
    id = serializers.RegexField(r'^([-\w]+\.)*[-\w]+\Z')
    probes = serializers.DictField(
        child=FeedProbeSerializer()
    )

    def get_name(self, url):
        return self.validated_data["name"]

    def iter_feed_probes(self):
        feed_id = self.validated_data["id"]
        for probe_id, probe_validated_data in self.validated_data["probes"].items():
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
    feed_serializer = get_feed_serializer(feed.url)
    current_feed_name = feed_serializer.get_name(feed.url)
    if not feed.name == current_feed_name:
        feed.name = current_feed_name
        feed.save()
    seen_keys = []
    for feed_probe_key, feed_probe_data in feed_serializer.iter_feed_probes():
        feed_probe_data["archived_at"] = None
        feed_probe, created = FeedProbe.objects.update_or_create(feed=feed, key=feed_probe_key,
                                                                 defaults=feed_probe_data)
        seen_keys.append(feed_probe.key)
    feed.feedprobe_set.exclude(key__in=seen_keys, archived_at__isnull=True).update(archived_at=timezone.now())


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
