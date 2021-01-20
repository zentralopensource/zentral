import logging
from rest_framework import serializers
from .models import Bundle, Configuration, Rule, Target


logger = logging.getLogger("zentral.contrib.santa.serializers")


class RuleUpdateSerializer(serializers.Serializer):
    policy = serializers.ChoiceField(choices=["ALLOWLIST", "ALLOWLIST_COMPILER", "BLOCKLIST", "SILENT_BLOCKLIST"])
    rule_type = serializers.ChoiceField(choices=[k for k, _ in Target.TYPE_CHOICES])
    sha256 = serializers.RegexField(r'^[a-f0-9]{64}\Z')
    custom_msg = serializers.CharField(required=False)
    serial_numbers = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    primary_users = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )
    tags = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False,
    )

    def validate_policy(self, value):
        try:
            return getattr(Rule, value)
        except AttributeError:
            raise serializers.ValidationError(f"Unknown policy: {value}")

    def validate(self, data):
        if data["rule_type"] == Target.BUNDLE and not data["policy"] in Rule.BUNDLE_POLICIES:
            raise serializers.ValidationError("Wrong policy for BUNDLE rule")
        if data["policy"] != Rule.BLOCKLIST and "custom_msg" in data:
            if data["custom_msg"]:
                raise serializers.ValidationError("Custom message can only be set on BLOCKLIST rules")
            del data["custom_msg"]
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
            self.configurations = Configuration.objects.all()
        # validate rules
        keys = set([])
        rule_errors = {}
        for rule_id, rule in enumerate(data.get("rules", [])):
            key = rule["rule_type"], rule["sha256"]
            if key in keys:
                rule_errors[str(rule_id)] = {"non_field_errors": ["duplicated"]}
            keys.add(key)
            # TODO: optimize
            if (Rule.objects.exclude(ruleset__name=data["name"])
                            .filter(
                                configuration__in=self.configurations,
                                target__type=rule["rule_type"], target__sha256=rule["sha256"]
                            ).exists()):
                rule_errors[str(rule_id)] = {"non_field_errors": ["conflict"]}
            elif (
                rule["rule_type"] == Target.BUNDLE and
                not Bundle.objects.filter(target__sha256=rule["sha256"],
                                          uploaded_at__isnull=False).exists()
            ):
                rule_errors[str(rule_id)] = {"non_field_errors": ["bundle unknown or not uploaded"]}
        if rule_errors:
            raise serializers.ValidationError({"rules": rule_errors})
        return data

    def all_tag_names(self):
        return set(n for r in self.data["rules"] for n in r.get("tags", []))
