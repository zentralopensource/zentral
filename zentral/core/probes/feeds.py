from importlib import import_module
import json
from django.utils import timezone
import requests
from rest_framework import serializers
from zentral.conf import settings
from .models import Feed, FeedProbe


class FeedProbeSerializer(serializers.Serializer):
    model = serializers.CharField()
    name = serializers.CharField()
    body = serializers.JSONField()


class FeedSerializer(serializers.Serializer):
    name = serializers.CharField()
    id = serializers.RegexField(r'^([a-z0-9\-]+\.)*[a-z0-9]+\Z')
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
    r = requests.get(url, stream=True)
    r.raise_for_status()
    feed_data = json.loads(r.text.replace("\\\n", " "))
    for feed_serializer_cls in get_feed_serializer_classes():
        feed_serializer = feed_serializer_cls(data=feed_data)
        if feed_serializer.is_valid():
            return feed_serializer
        else:
            import pprint
            print(feed_serializer_cls)
            pprint.pprint(feed_serializer.errors)
    raise ValueError("Unknown feed type")


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
