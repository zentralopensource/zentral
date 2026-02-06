from datetime import datetime
from itertools import chain
import logging
import os.path

from django.db import transaction
from django.db.models import F
from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .events import post_santa_rule_update_event
from .models import Configuration, Rule, Target, Enrollment
from .forms import cleanup_target_identifier


logger = logging.getLogger("zentral.contrib.santa.serializers")


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = '__all__'


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    plist_download_url = serializers.SerializerMethodField()
    configuration_profile_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        exclude = ('distributor_content_type', 'distributor_pk',)

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_artifact_download_url(self, view_name, obj):
        path = reverse(f"santa_api:{view_name}", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

    def get_plist_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_plist", obj)

    def get_configuration_profile_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_configuration_profile", obj)

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret_tags = secret_data.pop("tags", [])
        secret = EnrollmentSecret.objects.create(**secret_data)
        if secret_tags:
            secret.tags.set(secret_tags)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment

    def update(self, instance, validated_data):
        secret_serializer = self.fields["secret"]
        secret_data = validated_data.pop('secret')
        secret_serializer.update(instance.secret, secret_data)
        return super().update(instance, validated_data)


class RuleSerializer(serializers.ModelSerializer):
    target_type = serializers.ChoiceField(choices=[c[0] for c in Target.Type.rule_choices()], source="target.type")
    target_identifier = serializers.CharField(source="target.identifier")
    ruleset = serializers.PrimaryKeyRelatedField(read_only=True)
    version = serializers.IntegerField(default=1, read_only=True)

    class Meta:
        model = Rule
        exclude = ("target",)

    def validate(self, data):
        target_type = data["target_type"] = data["target"].get("type")
        target_identifier = data["target_identifier"] = data["target"].get("identifier")
        data.pop("target")

        # users conflicts
        primary_users = data.get("primary_users", [])
        excluded_primary_users = data.get("excluded_primary_users", [])
        primary_user_conflicts = ", ".join(f"'{u}'" for u in primary_users if u in excluded_primary_users)
        if primary_user_conflicts:
            raise serializers.ValidationError(
                {"primary_users": f"{primary_user_conflicts} in both included and excluded"}
            )
        # serial number conflicts
        serial_numbers = data.get("serial_numbers", [])
        excluded_serial_numbers = data.get("excluded_serial_numbers", [])
        serial_number_conflicts = ", ".join(f"'{sn}'" for sn in serial_numbers if sn in excluded_serial_numbers)
        if serial_number_conflicts:
            raise serializers.ValidationError(
                {"serial_numbers": f"{serial_number_conflicts} in both included and excluded"}
            )
        # tag conflicts
        tags = data.get("tags", [])
        excluded_tags = data.get("excluded_tags", [])
        tag_conflicts = ", ".join(f"'{t.name}'" for t in tags if t in excluded_tags)
        if tag_conflicts:
            raise serializers.ValidationError({"tags": f"{tag_conflicts} in both included and excluded"})

        # identifier
        if target_identifier:
            target_identifier = cleanup_target_identifier(target_type, target_identifier)
            if not target_identifier:
                raise serializers.ValidationError({"target_identifier": f"Invalid {target_type} identifier"})

        # Only one rule per target allowed for a given configuration
        test_qs = Rule.objects.filter(
            configuration=data["configuration"],
            target__type=target_type,
            target__identifier=target_identifier
        )
        if self.instance:
            test_qs = test_qs.exclude(pk=self.instance.pk)
        if test_qs.count():
            raise serializers.ValidationError({"target": "rule already exists for this target"})

        # policy
        policy = Rule.Policy(data.get("policy"))
        if not policy.compatible_with_custom_msg_and_url:
            errors = {}
            for field in ["custom_msg", "custom_url"]:
                if data.get(field):
                    errors[field] = "Cannot be set for this rule policy"
            if errors:
                raise serializers.ValidationError(errors)
        if policy is Rule.Policy.CEL:
            if not data.get("cel_expr"):
                raise serializers.ValidationError({"cel_expr": "This field is required for CEL rules"})
        elif data.get("cel_expr"):
            raise serializers.ValidationError({"cel_expr": "Can only be set on CEL rules"})

        return data

    def create(self, validated_data):
        target, _ = Target.objects.get_or_create(
            type=validated_data.pop("target_type"),
            identifier=validated_data.pop("target_identifier")
        )
        validated_data["target"] = target
        rule = super().create(validated_data)
        transaction.on_commit(lambda: post_santa_rule_update_event(self.context["request"],
                                                                   {"rule": rule.serialize_for_event(),
                                                                    "result": "created"}))
        return rule

    def update(self, instance, validated_data):
        target, _ = Target.objects.get_or_create(
            type=validated_data.pop("target_type"),
            identifier=validated_data.pop("target_identifier")
        )
        validated_data["target"] = target
        updates = {}
        bump_version = False

        for attr, value in validated_data.items():
            removed_items = added_items = None
            instance_value = getattr(instance, attr)

            if attr in ("tags", "excluded_tags"):
                updated_value, initial_value = set(value), set(instance_value.all())
                removed, added = initial_value.difference(updated_value), updated_value.difference(initial_value)
            elif attr in ("primary_users", "excluded_primary_users", "serial_numbers", "excluded_serial_numbers"):
                updated_value, initial_value = set(value), set(instance_value)
                removed, added = initial_value.difference(updated_value), updated_value.difference(initial_value)
            else:
                updated_value, initial_value = value, instance_value
                removed, added = initial_value, updated_value

            if updated_value != initial_value:
                if attr in ("tags", "excluded_tags"):
                    added_items = [{"pk": t.pk, "name": t.name} for t in added]
                    removed_items = [{"pk": t.pk, "name": t.name} for t in removed]
                elif attr in ("primary_users", "excluded_primary_users", "serial_numbers", "excluded_serial_numbers"):
                    added_items = sorted(added)
                    removed_items = sorted(removed)
                elif attr in ("target", "configuration"):
                    kwargs = {}
                    if attr == "configuration":
                        kwargs["keys_only"] = True
                    added_items = added.serialize_for_event(**kwargs)
                    removed_items = removed.serialize_for_event(**kwargs)
                elif attr == "policy":
                    added_items = Rule.Policy(added).name
                    removed_items = Rule.Policy(removed).name
                else:
                    added_items = added
                    removed_items = removed
                    if attr in ("cel_expr", "custom_msg", "custom_url"):
                        bump_version = True

            if removed_items:
                updates.setdefault("removed", {})[attr] = removed_items
            if added_items:
                updates.setdefault("added", {})[attr] = added_items

        if updates:
            if bump_version:
                validated_data["version"] = F("version") + 1
            rule = super().update(instance, validated_data)
            rule.refresh_from_db()
            transaction.on_commit(lambda: post_santa_rule_update_event(self.context["request"], {
                "rule": instance.serialize_for_event(),
                "result": "updated",
                "updates": updates
            }))
        else:
            rule = instance
        return rule


class RuleUpdateSerializer(serializers.Serializer):
    policy = serializers.ChoiceField(choices=["ALLOWLIST", "ALLOWLIST_COMPILER", "BLOCKLIST", "SILENT_BLOCKLIST"])
    rule_type = serializers.ChoiceField(choices=[k for k, _ in Target.Type.rule_choices()])
    sha256 = serializers.RegexField(r'^[a-f0-9]{64}\Z', required=False)  # Legacy field  TODO remove eventually
    identifier = serializers.CharField(required=False)
    custom_msg = serializers.CharField(required=False)
    custom_url = serializers.CharField(required=False)
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
            return getattr(Rule.Policy, value)
        except AttributeError:
            raise serializers.ValidationError(f"Unknown policy: {value}")

    def validate(self, data):
        rule_type = Target.Type(data["rule_type"])
        # identifier (or sha256)
        identifier = data.pop("identifier", None)
        sha256 = data.pop("sha256", None)
        if not identifier and not sha256:
            raise serializers.ValidationError({"identifier": "This field is required"})
        elif identifier and sha256:
            raise serializers.ValidationError("sha256 and identifier cannot be both set")
        elif sha256:
            if not rule_type.has_sha256_identifier:
                raise serializers.ValidationError({"sha256": f"This field cannot be used in a {rule_type} rule"})
            else:
                data["identifier"] = sha256
        elif identifier:
            identifier = cleanup_target_identifier(rule_type, identifier)
            if not identifier:
                raise serializers.ValidationError({"identifier": f"Invalid {rule_type} identifier"})
            data["identifier"] = identifier
        # custom message only with blocklist / CEL rule
        if not data["policy"].compatible_with_custom_msg_and_url:
            if data.get("custom_msg"):
                raise serializers.ValidationError("Custom message cannot be set for this rule policy")
            if data.get("custom_url"):
                raise serializers.ValidationError("Custom URL cannot be set for this rule policy")
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
    for from_a, to_a in (("SHA-256", "sha_256"),
                         ("CDHash", "cdhash")):
        file_d[to_a] = fi_d.get(from_a)
    team_id = fi_d.get("Team ID")
    signing_id = fi_d.get("Signing ID")
    if team_id and signing_id:
        if not signing_id.startswith(team_id):
            signing_id = f"{team_id}:{signing_id}"
    if signing_id:
        file_d["signing_id"] = signing_id
    path = fi_d.get("Path")
    file_d["path"], file_d["name"] = os.path.split(path)
    for a, val in (("bundle", _build_bundle_tree_from_santa_fileinfo(fi_d)),
                   ("signed_by", _build_siging_chain_tree_from_santa_fileinfo(fi_d))):
        file_d[a] = val
    return file_d
