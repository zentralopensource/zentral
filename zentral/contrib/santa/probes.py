import logging
from django.core.urlresolvers import reverse_lazy
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers
from zentral.core.probes import register_probe_class
from zentral.core.probes.base import BaseProbe, BaseProbeSerializer

logger = logging.getLogger("zentral.contrib.santa.probes")


class Rule(object):
    BLACKLIST = "BLACKLIST"
    WHITELIST = "WHITELIST"
    POLICY_CHOICES = (
        (BLACKLIST, _("Blacklist")),
        (WHITELIST, _("Whitelist"))
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

    def get_store_links(self):
        search_dict = {'event_type': self.probe.forced_event_type}
        if self.rule_type == self.CERTIFICATE:
            search_dict['signing_chain.sha256'] = [self.sha256]
        else:
            search_dict['file_sha256'] = [self.sha256]
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

    def load_validated_data(self, validated_data):
        super().load_validated_data(validated_data)
        self.rules = [Rule(self, **rule_data)
                      for rule_data in validated_data["rules"]]
        self.can_delete_rules = len(self.rules) > 1
        self.blacklist_rule_keys = set((r.rule_type, r.sha256)
                                       for r in self.rules
                                       if r.policy == Rule.BLACKLIST)
        self.whitelist_rule_keys = set((r.rule_type, r.sha256)
                                       for r in self.rules
                                       if r.policy == Rule.WHITELIST)

    def get_extra_event_search_dict(self):
        # probe links. match all sha256 in the probe.
        probe_search_dict = {'event_type': self.forced_event_type}
        all_file_sha256 = []
        all_certificate_sha256 = []
        for rule in self.rules:
            if rule.rule_type == Rule.CERTIFICATE:
                all_certificate_sha256.append(rule.sha256)
            else:
                all_file_sha256.append(rule.sha256)
        # TODO BUG "AND" !!!
        if all_certificate_sha256:
            probe_search_dict['signing_chain.sha256'] = all_certificate_sha256
        if all_file_sha256:
            probe_search_dict['file_sha256'] = all_file_sha256
        return probe_search_dict

    def test_event(self, event):
        # inventory_filters, forced_event_type, payload_filters
        if not super().test_event(event):
            return False

        # find out if the probe has rules that could have triggered this event

        # test santa event decision
        payload = event.payload
        decision = payload.get("decision")
        if decision is None or decision in ["ALLOW_UNKNOWN", "BLOCK_UNKNOWN",
                                            "UNKNOWN",
                                            "BUNDLE_BINARY",
                                            "ALLOW_SCOPE", "BLOCK_SCOPE"]:
            # ALLOW_UNKNOWN in MONITOR mode
            # or BLOCK_UNKNOWN in LOCKDOWN mode
            # never a match for a SantaProbe
            # TODO: what is the meaning of UNKNOWN, SCOPE, BUNDLE_BINARY ?
            return False
        try:
            action, rule_type = decision.split("_")
        except (IndexError, TypeError):
            logger.warning("Unknown SantaEvent decision %s", decision)
            return False

        # probe rule keys from event decision
        if action == "BLOCK":
            # rule.policy == "BLACKLIST"
            probe_rule_keys = self.blacklist_rule_keys
        elif action == "ALLOW":
            # rule.policy == "WHITELIST"
            probe_rule_keys = self.whitelist_rule_keys
        else:
            logger.warning("Unknown SantaEvent decision %s", decision)
            return False

        if not probe_rule_keys:
            # this probe doesn't have any rule with a matching policy
            return False

        # extract payload sha256 with decision match type
        if rule_type == "BINARY":
            sha256_list = [payload["file_sha256"]]
        elif rule_type == "CERTIFICATE":
            sha256_list = [cert["sha256"] for cert in payload["signing_chain"]]
        else:
            logger.warning("Unknown SantaEvent decision %s", decision)
            return False

        # is there a matching rule in this probe ?
        if not any((rule_type, sha256) in probe_rule_keys
                   for sha256 in sha256_list):
            return False
        else:
            # there is one !
            return True


register_probe_class(SantaProbe)
