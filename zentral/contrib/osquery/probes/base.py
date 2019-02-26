import hashlib
from django.urls import reverse_lazy
from django.utils.functional import cached_property
from rest_framework import serializers
from zentral.core.probes import register_probe_class
from zentral.core.probes.base import BaseProbe, BaseProbeSerializer
from zentral.utils.sql import format_sql


class OsqueryResultProbe(BaseProbe):
    forced_event_type = 'osquery_result'
    hash_length = 8

    def test_event(self, event):
        if not super().test_event(event):
            return False
        query_name = event.payload.get("name", None)
        if query_name not in self.scheduled_queries:
            return False
        else:
            return True

    def iter_discovery_queries(self):
        yield from []

    def iter_scheduled_queries(self):
        raise NotImplementedError

    @cached_property
    def pack_discovery_queries(self):
        # ordering and no duplicates to group the queries from the different probes
        return sorted(set(self.iter_discovery_queries()))

    @cached_property
    def pack_key(self):
        if not self.pack_discovery_queries:
            # the queries in this probe will not be put in a pack
            return None
        # the queries in this probe need to be put in a pack
        # with the discovery queries
        h = hashlib.sha1()
        for dq in self.pack_discovery_queries:
            h.update(dq.encode("utf-8"))
        return h.hexdigest()[:self.hash_length]

    @cached_property
    def scheduled_queries(self):
        return dict((q.result_name, q)
                    for q in self.iter_scheduled_queries())


class OsqueryQuery(object):
    def __init__(self, probe, query, interval=3600,
                 description=None, value=None,
                 removed=True, snapshot=False,
                 platform=None, shard=None, version=None,
                 prefix="", hash_length=OsqueryResultProbe.hash_length):
        self.probe = probe
        self.query = query
        self.interval = interval
        self.description = description
        self.value = value
        self.removed = removed
        self.snapshot = snapshot
        self.platform = platform
        self.shard = shard
        self.version = version
        self.prefix = prefix
        self.hash_length = hash_length

    def get_query_html(self):
        if self.query:
            return format_sql(self.query)

    @cached_property
    def name(self):
        name_items = [self.probe.slug]
        if self.prefix:
            name_items.append(self.prefix)
        name_items.append(hashlib.sha1(self.query.encode("utf-8")).hexdigest()[:self.hash_length])
        return '_'.join(name_items)

    @cached_property
    def result_name(self):
        if self.probe.pack_key:
            # osquery will prefix the name of the query with the name of the pack
            # in the osquery result name keys
            prefix = "pack_{k}_".format(k=self.probe.pack_key)
        else:
            # no prefix in the 'schedule' queries
            prefix = ""
        return "{p}{n}".format(p=prefix, n=self.name)

    def get_store_links(self):
        return self.probe.get_store_links(event_type=self.probe.forced_event_type,
                                          name=self.result_name)

    def to_configuration(self):
        s = OsqueryQuerySerializer(instance=self)
        d = s.data
        for key, val in list(d.items()):
            if val is None:
                del d[key]
        platform = d.pop("platform", None)
        if platform:
            d["platform"] = ",".join(platform)
        return d


class OsqueryQuerySerializer(serializers.Serializer):
    PLATFORM_CHOICES = (('arch', 'Arch'),
                        ('amazon', 'Amazon Linux'),  # Red Hat based
                        ('centos', 'CentOS'),  # Red Hat based
                        ('darwin', 'macOS'),
                        ('debian', 'Debian'),  # Debian based
                        ('fedora', 'Fedora'),  # Red Hat based
                        ('freebsd', 'FreeBSD'),
                        ('funtoo', 'Funtoo Linux'),  # Gentoo based
                        ('gentoo', 'Gentoo Linux'),  # Gentoo based
                        ('linux', 'Linux'),
                        ('manjaro', 'Manjaro Linux'),
                        ('oracle', 'Oracle Linux'),  # Red Hat based
                        ('redhat', 'Red Hat'),  # TODO WHY?
                        ('posix', 'POSIX'),  # TODO WHY?
                        ('rhel', 'Red Hat Enterprise Linux'),  # Red Hat based
                        ('scientific', 'Scientific Linux'),  # Red Hat based
                        ('ubuntu', 'Ubuntu'),  # Debian based
                        ('windows', 'Windows'),
                        )
    query = serializers.CharField()
    interval = serializers.IntegerField(min_value=10, max_value=2678400, default=3600)
    description = serializers.CharField(required=False,
                                        help_text="Description of what this query does. Not required")
    value = serializers.CharField(required=False,
                                  help_text="Why is this query relevant. Not required")
    removed = serializers.BooleanField(required=False,
                                       help_text='Include {"action": "removed"} results?')
    snapshot = serializers.BooleanField(required=False,
                                        help_text='Run this query in "snapshot" mode')
    platform = serializers.MultipleChoiceField(choices=PLATFORM_CHOICES, required=False)
    shard = serializers.IntegerField(min_value=1, max_value=100, required=False,
                                     help_text="Restrict this query to a percentage (1-100) of target hosts")
    version = serializers.RegexField('^[0-9]+\.[0-9]+\.[0-9]+\Z', required=False,
                                     help_text="Only run on osquery versions greater than or equal-to *")

    def validate(self, data):
        removed = data.get("removed", False)
        snapshot = data.get("snapshot", False)
        if removed and snapshot:
            raise serializers.ValidationError('{"action": "removed"} results are not available in "snapshot" mode')
        return data


class OsqueryProbeSerializer(BaseProbeSerializer):
    discovery = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    queries = serializers.ListField(
        child=OsqueryQuerySerializer(),
    )


class OsqueryProbe(OsqueryResultProbe):
    serializer_class = OsqueryProbeSerializer
    model_display = 'osquery'
    create_url = reverse_lazy("osquery:create_probe")
    template_name = "osquery/probe.html"

    def load_validated_data(self, data):
        super().load_validated_data(data)
        self.discovery = data.get('discovery', [])
        self.queries = [OsqueryQuery(probe=self, **query_data)
                        for query_data in data["queries"]]
        self.can_delete_queries = len(self.queries) > 1

    def iter_discovery_queries(self):
        yield from self.discovery

    def iter_scheduled_queries(self):
        yield from self.queries

    def get_discovery_display(self):
        for discovery in self.discovery:
            yield format_sql(discovery)

    def get_extra_event_search_dict(self):
        return {'event_type': self.forced_event_type,
                'name__regexp': '(pack_[0-9a-f]{{{l}}}_)?{s}_[0-9a-f]{{{l}}}'.format(s=self.slug, l=self.hash_length)}


register_probe_class(OsqueryProbe)
