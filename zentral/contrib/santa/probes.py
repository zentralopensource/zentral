import logging
from django.core.urlresolvers import reverse_lazy
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

    def get_payload_filter_kwargs(self):
        f = {}
        if self.rule_type == self.CERTIFICATE:
            f['signing_chain.sha256'] = [self.sha256]
            if self.policy == self.BLACKLIST:
                f['decision'] = ['BLOCK_CERTIFICATE']
            elif self.policy == self.WHITELIST:
                f['decision'] = ['ALLOW_CERTIFICATE']
        else:
            f['file_sha256'] = [self.sha256]
            if self.policy == self.BLACKLIST:
                f['decision'] = ['BLOCK_BINARY']
            elif self.policy == self.WHITELIST:
                f['decision'] = ['ALLOW_BINARY']
        return f

    def get_store_links(self):
        search_dict = {'event_type': [self.probe.forced_event_type]}
        search_dict.update(self.get_payload_filter_kwargs())
        return self.probe.get_store_links(**search_dict)

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
    sha256 = serializers.RegexField('^[a-f0-9]{64}\Z')
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
            f = r.get_payload_filter_kwargs()
            self.payload_filters.append(PayloadFilter(**f))


register_probe_class(SantaProbe)
