from datetime import datetime
from itertools import chain
import logging
import os.path
from rest_framework import serializers
from .models import Bundle, Configuration, Rule, Target
from .forms import test_sha256, test_team_id


logger = logging.getLogger("zentral.contrib.santa.serializers")


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = '__all__'


class RuleTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = ("type", "identifier")


class RuleSerializer(serializers.ModelSerializer):
    target = RuleTargetSerializer()

    class Meta:
        model = Rule
        fields = '__all__'


class RuleUpdateSerializer(serializers.Serializer):
    policy = serializers.ChoiceField(choices=["ALLOWLIST", "ALLOWLIST_COMPILER", "BLOCKLIST", "SILENT_BLOCKLIST"])
    rule_type = serializers.ChoiceField(choices=[k for k, _ in Target.TYPE_CHOICES])
    sha256 = serializers.RegexField(r'^[a-f0-9]{64}\Z', required=False)  # Legacy field  TODO remove eventually
    identifier = serializers.RegexField(r'^[a-zA-Z0-9]{10,64}\Z', required=False)
    custom_msg = serializers.CharField(required=False)
    description = serializers.CharField(required=False)
    serial_numbers = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    excluded_serial_numbers = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    primary_users = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    excluded_primary_users = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    tags = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    excluded_tags = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )

    def validate_policy(self, value):
        try:
            return getattr(Rule, value)
        except AttributeError:
            raise serializers.ValidationError(f"Unknown policy: {value}")

    def validate(self, data):
        rule_type = data["rule_type"]
        # bundle rule policy
        if rule_type == Target.BUNDLE and not data["policy"] in Rule.BUNDLE_POLICIES:
            raise serializers.ValidationError("Wrong policy for BUNDLE rule")
        # identifier (or sha256)
        identifier = data.pop("identifier", None)
        sha256 = data.pop("sha256", None)
        if not identifier and not sha256:
            raise serializers.ValidationError({"identifier": "This field is required"})
        elif identifier and sha256:
            raise serializers.ValidationError("sha256 and identifier cannot be both set")
        elif sha256:
            if rule_type == Target.TEAM_ID:
                raise serializers.ValidationError({"sha256": "This field cannot be used in a Team ID rule"})
            else:
                data["identifier"] = sha256
        elif identifier:
            if rule_type == Target.TEAM_ID:
                identifier = identifier.upper()
                if test_team_id(identifier):
                    data["identifier"] = identifier
                else:
                    raise serializers.ValidationError({"identifier": "Invalid Team ID"})
            else:
                identifier = identifier.lower()
                if test_sha256(identifier):
                    data["identifier"] = identifier
                else:
                    raise serializers.ValidationError({"identifier": "Invalid sha256"})
        # custom message only with blocklist rule
        if data["policy"] != Rule.BLOCKLIST and "custom_msg" in data:
            if data["custom_msg"]:
                raise serializers.ValidationError("Custom message can only be set on BLOCKLIST rules")
            del data["custom_msg"]
        # scope conflicts
        for attr in ("serial_numbers", "primary_users", "tags"):
            if set(data.get(attr, [])).intersection(set(data.get(f"excluded_{attr}", []))):
                raise serializers.ValidationError(f"Conflict between {attr} and excluded_{attr}")
        return data


class RuleSetUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(min_length=1)
    configurations = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    rules = serializers.ListField(
        child=RuleUpdateSerializer(),
    )

    def validate_configurations(self, value):
        self.configurations = list(Configuration.objects.filter(name__in=value))
        unknown_configurations = set(value) - set(cfg.name for cfg in self.configurations)
        if unknown_configurations:
            raise serializers.ValidationError(
                "Unknown configuration{}: {}".format(
                    "" if len(unknown_configurations) == 1 else "s",
                    ", ".join(sorted(unknown_configurations))
                )
            )
        return self.configurations

    def validate(self, data):
        # all configurations if no configurations key
        if "configurations" not in data:
            self.configurations = Configuration.objects.all().order_by("pk")
        # validate rules
        keys = set([])
        rule_errors = {}
        for rule_id, rule in enumerate(data.get("rules", [])):
            key = rule["rule_type"], rule["identifier"]
            if key in keys:
                rule_errors[str(rule_id)] = {
                    "non_field_errors": ["{rule_type}/{identifier}: duplicated".format(**rule)]
                }
            keys.add(key)
            # TODO: optimize
            if (Rule.objects.exclude(ruleset__name=data["name"])
                            .filter(
                                configuration__in=self.configurations,
                                target__type=rule["rule_type"], target__identifier=rule["identifier"]
                            ).exists()):
                rule_errors[str(rule_id)] = {
                    "non_field_errors": ["{rule_type}/{identifier}: conflict".format(**rule)]
                }
            elif (
                rule["rule_type"] == Target.BUNDLE and
                not Bundle.objects.filter(target__identifier=rule["identifier"],
                                          uploaded_at__isnull=False).exists()
            ):
                rule_errors[str(rule_id)] = {
                    "non_field_errors": ["{rule_type}/{identifier}: bundle unknown or not uploaded".format(**rule)]
                }
        if rule_errors:
            raise serializers.ValidationError({"rules": rule_errors})
        return data

    def all_tag_names(self):
        return set(n for r in self.data["rules"] for n in chain(r.get("tags", []), r.get("excluded_tags", [])))


# Santa fileinfo


def _build_certificate_tree_from_santa_fileinfo_cert(in_d):
    out_d = {}
    for from_a, to_a, is_dt in (("Common Name", "common_name", False),
                                ("Organization", "organization", False),
                                ("Organizational Unit", "organizational_unit", False),
                                ("SHA-256", "sha_256", False),
                                ("Valid From", "valid_from", True),
                                ("Valid Until", "valid_until", True)):
        val = in_d.get(from_a)
        if is_dt:
            val = datetime.strptime(val, "%Y/%m/%d %H:%M:%S %z")
        out_d[to_a] = val
    return out_d


def _build_siging_chain_tree_from_santa_fileinfo(fi_d):
    fi_signing_chain = fi_d.get("Signing Chain")
    if not fi_signing_chain:
        return
    signing_chain = None
    current_cert = None
    for in_d in fi_signing_chain:
        cert_d = _build_certificate_tree_from_santa_fileinfo_cert(in_d)
        if current_cert:
            current_cert["signed_by"] = cert_d
        else:
            signing_chain = cert_d
        current_cert = cert_d
    return signing_chain


def _build_bundle_tree_from_santa_fileinfo(fi_d):
    bundle_d = {}
    for from_a, to_a in (("Bundle Name", "bundle_name"),
                         ("Bundle Version", "bundle_version"),
                         ("Bundle Version Str", "bundle_version_str")):
        val = fi_d.get(from_a)
        if val:
            bundle_d[to_a] = val
    if bundle_d:
        return bundle_d


def build_file_tree_from_santa_fileinfo(fi_d):
    file_d = {
        "source": {
            "module": "zentral.contrib.santa",
            "name": "Santa fileinfo"
        }
    }
    for from_a, to_a in (("SHA-256", "sha_256"),):
        file_d[to_a] = fi_d.get(from_a)
    path = fi_d.get("Path")
    file_d["path"], file_d["name"] = os.path.split(path)
    for a, val in (("bundle", _build_bundle_tree_from_santa_fileinfo(fi_d)),
                   ("signed_by", _build_siging_chain_tree_from_santa_fileinfo(fi_d))):
        file_d[a] = val
    return file_d
