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
from .models import Bundle, Configuration, Rule, Target, Enrollment, translate_rule_policy
from .forms import test_sha256, test_team_id


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


class RuleMixin:

    def validate_scope(self, data):

        # primary user conflicts
        primary_users = data.get("primary_users", [])
        excluded_primary_users = data.get("excluded_primary_users", [])
        primary_user_conflicts = ", ".join(f"'{u}'" for u in primary_users
                                           if u in excluded_primary_users)
        if primary_user_conflicts:
            raise serializers.ValidationError(
                {"primary_users": f"{primary_user_conflicts} in both included and excluded"}
            )

        # serial number conflicts
        serial_numbers = data.get("serial_numbers", [])
        excluded_serial_numbers = data.get("excluded_serial_numbers", [])
        serial_number_conflicts = ", ".join(f"'{sn}'" for sn in serial_numbers
                                            if sn in excluded_serial_numbers)
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


class RuleSerializer(serializers.ModelSerializer, RuleMixin):
    target_type = serializers.ChoiceField(choices=[c[0] for c in Target.TYPE_CHOICES], source="target.type")
    target_identifier = serializers.CharField(source="target.identifier")
    ruleset = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Rule
        exclude = ("target",)

    def validate(self, data):
        target_type = data["target"].get("type")
        target_identifier = data["target"].get("identifier")
        configuration = data.get("configuration")

        # identifier
        if target_identifier:
            if target_type is Target.TEAM_ID:
                target_identifier = target_identifier.upper()
                if not test_team_id(target_identifier):
                    raise serializers.ValidationError({"target_identifier": "Invalid Team ID"})
            else:
                target_identifier = target_identifier.lower()
                if not test_sha256(target_identifier):
                    raise serializers.ValidationError({"target_identifier": "Invalid sha256"})

        # duplicated rule
        if not self.instance:
            if target_type and target_identifier and Rule.objects.filter(
                    configuration=configuration,
                    target__type=target_type,
                    target__identifier=target_identifier).count():
                raise serializers.ValidationError({"target": "rule already exists for this target"})
        else:
            # target does not exist on update
            if not Target.objects.filter(type=target_type, identifier=target_identifier).exists():
                raise serializers.ValidationError({"target": "does not exist!"})

        # bundle target checks
        if target_type == Target.BUNDLE:
            try:
                bundle = Bundle.objects.get(target__identifier=target_identifier)
            except Bundle.DoesNotExist:
                raise serializers.ValidationError({"target_type": f'Bundle for {target_identifier} does not exist.'})
            else:
                if not bundle.uploaded_at:
                    raise serializers.ValidationError({"bundle": "This bundle has not been uploaded yet."})

        # policy
        try:
            policy = int(data.get("policy"))
        except (TypeError, ValueError):
            pass
        else:
            # use custom message only on blocklist rules
            if policy is not Rule.BLOCKLIST:
                if data.get("custom_msg"):
                    raise serializers.ValidationError({"custom_msg": "Can only be set on BLOCKLIST rules"})
            if target_type is Target.BUNDLE:
                if policy not in Rule.BUNDLE_POLICIES:
                    raise serializers.ValidationError({"policy": f"Policy {policy} not allowed for bundles."})
        
        # add target_type, target_identifier for create
        if not self.instance:
            data["target_type"] = target_type
            data["target_identifier"] = target_identifier

        # remove target
        data.pop("target")

        # validate scope
        self.validate_scope(data)
        return data

    def create(self, validated_data):
        # create the target from target_type and target_identifier
        target_type = validated_data.pop("target_type")
        target_identifier = validated_data.pop("target_identifier")
        target, _ = Target.objects.get_or_create(type=target_type, identifier=target_identifier)

        rule = Rule.objects.create(
            configuration=validated_data["configuration"],
            target=target,
            policy=validated_data["policy"],
            custom_msg=validated_data.get("custom_msg", ""),
            description=validated_data.get("description", ""),
            serial_numbers=validated_data.get("serial_numbers") or [],
            excluded_serial_numbers=validated_data.get("excluded_serial_numbers") or [],
            primary_users=validated_data.get("primary_users") or [],
            excluded_primary_users=validated_data.get("excluded_primary_users") or []
        )
        tags = validated_data.get("tags")
        if tags:
            rule.tags.set(tags)
        excluded_tags = validated_data.get("excluded_tags")
        if excluded_tags:
            rule.excluded_tags.set(excluded_tags)
        return rule

    def update(self, instance, validated_data):

        updates = {}
        updated = False
        rule = instance

        # policy
        policy = validated_data["policy"]
        if policy != instance.policy:
            updates.setdefault("removed", {})["policy"] = translate_rule_policy(instance.policy)
            updated = True
            updates.setdefault("added", {})["policy"] = translate_rule_policy(policy)

        # custom_msg
        custom_msg = validated_data.get("custom_msg")
        if custom_msg != instance.custom_msg:
            instance.version = F("version") + 1
            instance.save()
            instance.refresh_from_db()
            updated = True
            updates.setdefault("removed", {})["custom_msg"] = instance.custom_msg
            if custom_msg:
                updates.setdefault("added", {})["custom_msg"] = custom_msg

        # description
        description = validated_data.get("description")
        if description != instance.description:
            updates.setdefault("removed", {})["description"] = instance.description
            updated = True
            if description:
                updates.setdefault("added", {})["description"] = description

        # serial_numbers
        if validated_data.get("serial_numbers"):
            serial_numbers = set(validated_data.get("serial_numbers"))
            old_serial_numbers = set(instance.serial_numbers)
            if serial_numbers != instance.serial_numbers:
                updated = True
                added_serial_numbers = serial_numbers - old_serial_numbers
                if added_serial_numbers:
                    updates.setdefault("added", {})["serial_numbers"] = sorted(added_serial_numbers)
                removed_serial_numbers = old_serial_numbers - serial_numbers
                if removed_serial_numbers:
                    updates.setdefault("removed", {})["serial_numbers"] = sorted(removed_serial_numbers)

        # excluded_serial_numbers
        if validated_data.get("excluded_serial_numbers"):
            excluded_serial_numbers = set(validated_data.get("excluded_serial_numbers"))
            old_excluded_serial_numbers = set(instance.excluded_serial_numbers)
            if excluded_serial_numbers != instance.excluded_serial_numbers:
                updated = True
                added_excluded_serial_numbers = excluded_serial_numbers - old_excluded_serial_numbers
                if added_excluded_serial_numbers:
                    updates.setdefault("added", {})["excluded_serial_numbers"] = \
                        sorted(added_excluded_serial_numbers)
                removed_excluded_serial_numbers = old_excluded_serial_numbers - excluded_serial_numbers
                if removed_excluded_serial_numbers:
                    updates.setdefault("removed", {})["excluded_serial_numbers"] = \
                        sorted(removed_excluded_serial_numbers)

        # primary_users
        if validated_data.get("primary_users"):
            primary_users = set(validated_data.get("primary_users"))
            old_primary_users = set(instance.primary_users)
            if primary_users != instance.primary_users:
                updated = True
                added_primary_users = primary_users - old_primary_users
                if added_primary_users:
                    updates.setdefault("added", {})["primary_users"] = sorted(added_primary_users)
                removed_primary_users = old_primary_users - primary_users
                if removed_primary_users:
                    updates.setdefault("removed", {})["primary_users"] = sorted(removed_primary_users)

        # excluded_primary_users
        if validated_data.get("excluded_primary_users"):
            excluded_primary_users = set(validated_data.get("excluded_primary_users"))
            old_excluded_primary_users = set(instance.excluded_primary_users)
            if excluded_primary_users != instance.excluded_primary_users:
                updated = True
                added_excluded_primary_users = excluded_primary_users - old_excluded_primary_users
                if added_excluded_primary_users:
                    updates.setdefault("added", {})["excluded_primary_users"] = sorted(added_excluded_primary_users)
                removed_excluded_primary_users = old_excluded_primary_users - excluded_primary_users
                if removed_excluded_primary_users:
                    updates.setdefault("removed", {})["excluded_primary_users"] = \
                        sorted(removed_excluded_primary_users)

        if updated:
            rule = super().update(instance, validated_data)

        # tags
        if validated_data.get("tags"):
            tags = set(validated_data.get("tags"))
            old_tags = set(instance.tags.all())
            if tags != old_tags:
                instance.tags.set(tags)
                instance.save()
                instance.refresh_from_db()
                added_tags = tags - old_tags
                if added_tags:
                    updates.setdefault("added", {})["tags"] = [{"pk": t.pk, "name": t.name} for t in added_tags]
                removed_tags = old_tags - tags
                if removed_tags:
                    updates.setdefault("removed", {})["tags"] = [{"pk": t.pk, "name": t.name} for t in removed_tags]

        # excluded_tags
        if validated_data.get("excluded_tags"):
            excluded_tags = set(validated_data.get("excluded_tags"))
            old_excluded_tags = set(instance.excluded_tags.all())
            if excluded_tags != list(instance.excluded_tags.all()):
                instance.excluded_tags.set(excluded_tags)
                instance.save()
                instance.refresh_from_db()
                added_excluded_tags = excluded_tags - old_excluded_tags
                if added_excluded_tags:
                    updates.setdefault("added", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                        for t in added_excluded_tags]
                removed_excluded_tags = old_excluded_tags - excluded_tags
                if removed_excluded_tags:
                    updates.setdefault("removed", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                          for t in removed_excluded_tags]
        if updates:
            rule_update_data = {"rule": instance.serialize_for_event(),
                                "result": "updated",
                                "updates": updates}
            transaction.on_commit(lambda: post_santa_rule_update_event(self.context.get("request"), rule_update_data))

        return rule


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
