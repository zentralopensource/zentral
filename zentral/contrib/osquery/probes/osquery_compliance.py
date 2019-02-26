import os.path
from django.urls import reverse_lazy
from rest_framework import serializers
from .base import register_probe_class, BaseProbeSerializer, OsqueryResultProbe, OsqueryQuery


class PreferenceFileKey(object):
    def __init__(self, key, min_value=None, value=None, max_value=None):
        self.key = key
        self.min_value = min_value
        self.value = value
        self.max_value = max_value

    def get_sql_fragment(self):
        tests = []
        if self.value is not None:
            tests.append("(value <> '{}')".format(self.value.replace("'", "''")))
        else:
            if self.min_value is not None:
                tests.append("(CAST(value as integer) < {})".format(self.min_value))
            if self.max_value is not None:
                tests.append("(CAST(value as integer) > {})".format(self.max_value))
        return "(key = '{}' and ({}))".format(self.key.replace("'", "''"),
                                              " or ".join(tests))


class PreferenceFileKeySerializer(serializers.Serializer):
    key = serializers.CharField()
    min_value = serializers.IntegerField(required=False)
    value = serializers.CharField(required=False)
    max_value = serializers.IntegerField(required=False)

    def validate(self, data):
        data = super().validate(data)
        min_value = data.get('min_value')
        value = data.get('value')
        max_value = data.get('max_value')
        if value is not None:
            if min_value:
                raise serializers.ValidationError("min value can't be set with value")
            if max_value:
                raise serializers.ValidationError("max value can't be set with value")
        elif min_value is None and max_value is None:
            raise serializers.ValidationError("min value, value and max value are empty")
        return data


class PreferenceFile(object):
    TYPE_CHOICES = (
        ('USERS', '/Users/%/Library/Preferences'),
        ('GLOBAL', '/Library/Preferences')
    )

    def __init__(self, probe, type, rel_path, keys, description=None, interval=3600):
        self.probe = probe
        self.type = type
        self.rel_path = rel_path
        self.keys = keys
        self.interval = interval
        self.description = description

    def get_rel_paths(self):
        exact_match = '%' not in self.rel_path
        rel_paths = [self.rel_path]
        if not exact_match:
            rel_paths.append('%/{}'.format(self.rel_path))
        return rel_paths, exact_match

    def get_root_dir(self):
        return dict(self.TYPE_CHOICES).get(self.type)

    def get_paths(self):
        return sorted(os.path.join(self.get_root_dir(), rel_path)
                      for rel_path in self.get_rel_paths()[0])

    def get_osquery_query(self):
        # query template
        if self.type == 'USERS':
            query_template = (
                "select username, filename, key, value "
                "from "
                "(select * from users where directory like '/Users/%') u, "
                "plist p, "
                "file f "
                "WHERE "
                "({rel_path_tests}) and ({key_tests}) "
                "and f.path = p.path"
            )
        else:
            query_template = (
                "select filename, key, value "
                "from "
                "plist p, file f "
                "WHERE "
                "({rel_path_tests}) and ({key_tests}) "
                "and f.path = p.path"
            )
        # rel_path tests
        rel_paths, exact_match = self.get_rel_paths()
        if exact_match:
            path_comp = '='
        else:
            path_comp = 'like'
        rel_path_tests = []
        for rel_path in rel_paths:
            if self.type == 'USERS':
                rel_path_test_tmpl = "(p.path {} u.directory || '/Library/Preferences/{}')"
            else:
                # there is not join with the users table
                rel_path_test_tmpl = "(p.path {} '/Library/Preferences/{}')"
            rel_path_tests.append(rel_path_test_tmpl.format(path_comp, rel_path))
        # key tests
        key_tests = [k.get_sql_fragment() for k in self.keys]
        # query
        query = query_template.format(rel_path_tests=" or ".join(rel_path_tests),
                                      key_tests=" or ".join(key_tests))
        return OsqueryQuery(probe=self.probe,
                            prefix='pf',
                            query=query,
                            removed=False,
                            interval=self.interval,
                            platform=['darwin'])


class PreferenceFileSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=PreferenceFile.TYPE_CHOICES)
    rel_path = serializers.CharField()
    keys = serializers.ListField(
        child=PreferenceFileKeySerializer()
    )
    description = serializers.CharField(required=False)
    interval = serializers.IntegerField(min_value=10, max_value=2678400, default=3600)


class FileChecksum(object):
    def __init__(self, probe, path, sha256, description=None, interval=3600):
        self.probe = probe
        self.path = path
        self.sha256 = sha256
        self.description = description
        self.interval = interval

    def get_sql_fragment(self):
        return "(path = '{}' and sha256 <> '{}')".format(self.path.replace("'", "''"),
                                                         self.sha256)

    def get_query_name_prefix(self):
        return "{}_fc_".format(self.probe.slug)

    def get_store_links(self):
        return self.probe.get_store_links(event_type=self.probe.forced_event_type,
                                          name__startswith=self.get_query_name_prefix(),
                                          **{'columns.path': self.path})


class FileChecksumSerializer(serializers.Serializer):
    path = serializers.CharField()
    sha256 = serializers.RegexField('^[a-f0-9]{64}\Z')
    description = serializers.CharField(required=False)
    interval = serializers.IntegerField(min_value=10, max_value=2678400, default=3600)


class OsqueryComplianceProbeSerializer(BaseProbeSerializer):
    preference_files = serializers.ListField(
        child=PreferenceFileSerializer(),
        required=False
    )
    file_checksums = serializers.ListField(
        child=FileChecksumSerializer(),
        required=False
    )


class OsqueryComplianceProbe(OsqueryResultProbe):
    serializer_class = OsqueryComplianceProbeSerializer
    model_display = "osquery compliance"
    create_url = reverse_lazy("osquery:create_compliance_probe")
    template_name = "osquery/compliance_probe.html"
    can_edit_payload_filters = False

    def load_validated_data(self, validated_data):
        super().load_validated_data(validated_data)
        self.preference_files = []
        for preference_file_data in validated_data.get("preference_files", []):
            keys = [PreferenceFileKey(**key_data)
                    for key_data in preference_file_data.pop("keys")]
            self.preference_files.append(PreferenceFile(probe=self,
                                                        keys=keys,
                                                        **preference_file_data))
        self.file_checksums = []
        for file_checksum_data in validated_data.get("file_checksums", []):
            self.file_checksums.append(FileChecksum(probe=self, **file_checksum_data))
        self.can_delete_items = len(self.preference_files) + len(self.file_checksums) > 1

    def _iter_file_checksums_scheduled_queries(self):
        # group file checksums by interval
        queries_fc = {}
        for file_checksum in self.file_checksums:
            queries_fc.setdefault(file_checksum.interval, []).append(file_checksum)
        for interval, file_checksums in queries_fc.items():
            query = "select path, sha256 from hash where ({})".format(
                " or ".join(fc.get_sql_fragment() for fc in file_checksums)
            )
            yield OsqueryQuery(probe=self,
                               query=query,
                               prefix="fc",
                               removed=False,
                               interval=interval)

    def iter_scheduled_queries(self):
        for pf in self.preference_files:
            yield pf.get_osquery_query()
        yield from self._iter_file_checksums_scheduled_queries()

    def get_extra_event_search_dict(self):
        # query name = probe slug + files or preferences
        return {'event_type': self.forced_event_type,
                'name__regexp': '{s}_(pf|fc)_[0-9a-f]{{{l}}}'.format(s=self.slug,
                                                                     l=self.hash_length)}


register_probe_class(OsqueryComplianceProbe)
