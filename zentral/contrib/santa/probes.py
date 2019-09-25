import logging
from django.urls import reverse_lazy
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers
from zentral.contrib.inventory.models import Certificate
from zentral.core.probes import register_probe_class
from zentral.core.probes.base import BaseProbe, BaseProbeSerializer, PayloadFilter
from .models import CollectedApplication

logger = logging.getLogger("zentral.contrib.santa.probes")


class Rule(object):
    BLACKLIST = "BLACKLIST"
    WHITELIST = "WHITELIST"
    REMOVE = "REMOVE"
    SILENT_BLACKLIST = "SILENT_BLACKLIST"
    POLICY_CHOICES = (
        (BLACKLIST, _("Blacklist")),
        (SILENT_BLACKLIST, _("Silent blacklist")),
        (WHITELIST, _("Whitelist")),
        (REMOVE, _("Remove"))
    )
    BINARY = "BINARY"
    CERTIFICATE = "CERTIFICATE"
    RULE_TYPE_CHOICES = (
        (BINARY, _("Binary")),
        (CERTIFICATE, _("Certificate")),
    )

    def __init__(self, probe, policy, rule_type, sha256, custom_msg=None):
        self.probe = probe
        self.policy = policy
        self.rule_type = rule_type
        self.sha256 = sha256
        self.custom_msg = custom_msg

    def _get_search_dict(self):
        search_dict = {}
        if self.rule_type == self.CERTIFICATE:
            search_dict["signing_chain.sha256"] = [self.sha256]
            if self.policy == self.BLACKLIST:
                search_dict["decision"] = ['BLOCK_CERTIFICATE']
            elif self.policy == self.WHITELIST:
                search_dict["decision"] = ['ALLOW_CERTIFICATE']
        else:
            search_dict["file_sha256"] = [self.sha256]
            if self.policy == self.BLACKLIST:
                search_dict["decision"] = ['BLOCK_BINARY']
            elif self.policy == self.WHITELIST:
                search_dict["decision"] = ['ALLOW_BINARY']
        return search_dict

    def get_payload_filter_data(self):
        return [
            {"attribute": attribute,
             "operator": PayloadFilter.IN,
             "values": values}
            for attribute, values in self._get_search_dict().items()
        ]

    def get_store_links(self):
        return self.probe.get_store_links(event_type=self.probe.forced_event_type,
                                          **self._get_search_dict())

    def get_policy_display(self):
        return dict(self.POLICY_CHOICES)[self.policy]

    def get_rule_type_display(self):
        return dict(self.RULE_TYPE_CHOICES)[self.rule_type]

    def to_configuration(self):
        s = RuleSerializer(instance=self)
        d = s.data
        for key, val in list(d.items()):
            if val is None:
                del d[key]
        return d

    @cached_property
    def collected_applications(self):
        if self.rule_type == self.BINARY:
            return list(CollectedApplication.objects.select_related("bundle").filter(sha_256=self.sha256))
        else:
            return []

    @cached_property
    def collected_certificates(self):
        if self.rule_type == self.CERTIFICATE:
            return list(Certificate.objects.filter(sha_256=self.sha256))
        else:
            return []


class RuleSerializer(serializers.Serializer):
    policy = serializers.ChoiceField(choices=Rule.POLICY_CHOICES)
    rule_type = serializers.ChoiceField(choices=Rule.RULE_TYPE_CHOICES)
    sha256 = serializers.RegexField(r'^[a-f0-9]{64}\Z')
    custom_msg = serializers.CharField(required=False)


class SantaProbeSerializer(BaseProbeSerializer):
    rules = serializers.ListField(
        child=RuleSerializer()
    )


class SantaProbe(BaseProbe):
    serializer_class = SantaProbeSerializer
    model_display = "santa"
    create_url = reverse_lazy("santa:create_probe")
    template_name = "santa/probe.html"
    forced_event_type = 'santa_event'
    can_edit_payload_filters = False

    def load_validated_data(self, validated_data):
        super().load_validated_data(validated_data)
        self.rules = [Rule(self, **rule_data)
                      for rule_data in validated_data["rules"]]
        self.can_delete_rules = len(self.rules) > 1
        for r in self.rules:
            self.payload_filters.append(
                PayloadFilter(r.get_payload_filter_data())
            )


register_probe_class(SantaProbe)
