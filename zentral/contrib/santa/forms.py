from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.db import transaction
from django.db.models import Count, F
from zentral.conf import settings
from zentral.contrib.inventory.models import Tag
from zentral.utils.forms import validate_sha256
from .events import post_santa_rule_update_event
from .models import Bundle, Configuration, Enrollment, Rule, RuleSet, Target, translate_rule_policy


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'
        widgets = {"event_detail_url": forms.Textarea(attrs={"cols": "40", "rows": "3"})}

    def clean(self):
        cleaned_data = super().clean()

        # no blocked path regex in lockdown mode
        client_mode = cleaned_data.get("client_mode")
        blocked_path_regex = cleaned_data.get("blocked_path_regex")
        if client_mode == Configuration.LOCKDOWN_MODE and blocked_path_regex:
            self.add_error("blocked_path_regex",
                           "Can't use a bloked path regex in Lockdown mode.")

        # client certificate authentication
        client_certificate_auth = cleaned_data.get("client_certificate_auth", False)
        client_auth_certificate_issuer_cn = cleaned_data.get("client_auth_certificate_issuer_cn")
        if client_auth_certificate_issuer_cn and not client_certificate_auth:
            self.add_error("client_certificate_auth",
                           "Needs to be checked to use Client auth certificate issuer CN")
        if (client_certificate_auth or client_auth_certificate_issuer_cn) and \
           "tls_hostname_for_client_cert_auth" not in settings["api"]:
            for field in ("client_certificate_auth", "client_auth_certificate_issuer_cn"):
                self.add_error(
                    field,
                    "The server requiring the client cert for authentication is not configured."
                )
        return cleaned_data


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = ("configuration",)

    def __init__(self, *args, **kwargs):
        # meta business unit not used in this enrollment form
        self.meta_business_unit = kwargs.pop("meta_business_unit", None)
        self.configuration = kwargs.pop("configuration", None)
        self.update_for = kwargs.pop("update_for", None)
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide configuration dropdown if configuration if fixed
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()


class BinarySearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name",
                                                         "size": 50}))


class BundleSearchForm(forms.Form):
    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "bundle name, id",
                                                         "size": 50}))


class CertificateSearchForm(forms.Form):
    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "common name, organization",
                                                          "size": 50}))


class RuleSearchForm(forms.Form):
    ruleset = forms.ModelChoiceField(queryset=RuleSet.objects.none(), required=False)
    target_type = forms.ChoiceField(choices=(("", "----"),) + Target.TYPE_CHOICES, required=False)
    policy = forms.ChoiceField(choices=(("", "----"),) + Rule.POLICY_CHOICES, required=False)
    sha256 = forms.CharField(required=False,
                             widget=forms.TextInput(attrs={"autofocus": "true",
                                                           "size": 32,
                                                           "placeholder": "sha256"}))

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        super().__init__(*args, **kwargs)
        self.fields["ruleset"].queryset = (
            RuleSet.objects.distinct()
                           .filter(rule__configuration=self.configuration)
                           .annotate(rule_count=Count("rule"))
                           .filter(rule_count__gte=1)
                           .order_by("name")
        )

    def get_queryset(self):
        qs = (Rule.objects.select_related("target")
                          .filter(configuration=self.configuration)
                          .order_by("-pk"))
        ruleset = self.cleaned_data.get("ruleset")
        if ruleset:
            qs = qs.filter(ruleset=ruleset)
        target_type = self.cleaned_data.get("target_type")
        if target_type:
            qs = qs.filter(target__type=target_type)
        policy = self.cleaned_data.get("policy")
        if policy:
            qs = qs.filter(policy=policy)
        sha256 = self.cleaned_data.get("sha256")
        if sha256:
            qs = qs.filter(target__sha256__icontains=sha256)
        return qs


class RuleForm(forms.Form):
    target_type = forms.ChoiceField(choices=Target.TYPE_CHOICES)
    target_sha256 = forms.CharField(validators=[validate_sha256])
    policy = forms.ChoiceField(choices=Rule.POLICY_CHOICES)
    custom_msg = forms.CharField(label="Custom message", required=False,
                                 widget=forms.Textarea(attrs={"cols": "40", "rows": "10"}))
    serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    primary_users = SimpleArrayField(forms.CharField(), required=False)
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        self.binary = kwargs.pop("binary", None)
        self.bundle = kwargs.pop("bundle", None)
        self.certificate = kwargs.pop("certificate", None)
        super().__init__(*args, **kwargs)
        if self.binary or self.bundle or self.certificate:
            del self.fields["target_type"]
            del self.fields["target_sha256"]
        if self.bundle:
            self.fields["policy"].choices = (
                (k, v)
                for k, v in Rule.POLICY_CHOICES
                if k in Rule.BUNDLE_POLICIES
            )
        if not any(k == Rule.BLOCKLIST for k, _ in self.fields["policy"].choices):
            del self.fields["custom_msg"]

    def clean(self):
        cleaned_data = super().clean()
        if self.binary:
            target_type = Target.BINARY
            target_sha256 = self.binary.sha_256
        elif self.bundle:
            target_type = Target.BUNDLE
            target_sha256 = self.bundle.target.sha256
        elif self.certificate:
            target_type = Target.CERTIFICATE
            target_sha256 = self.certificate.sha_256
        else:
            target_type = cleaned_data.get("target_type")
            target_sha256 = cleaned_data.get("target_sha256")

        if target_type and target_sha256 and Rule.objects.filter(configuration=self.configuration,
                                                                 target__type=target_type,
                                                                 target__sha256=target_sha256).count():
            self.add_error(None, "A rule for this target already exists")

        try:
            policy = int(cleaned_data.get("policy"))
        except (TypeError, ValueError):
            pass

        if target_type == Target.BUNDLE:
            try:
                bundle = Bundle.objects.get(target__sha256=target_sha256)
            except Bundle.DoesNotExist:
                self.add_error("bundle", 'Unknown bundle.')
            else:
                if not bundle.uploaded_at:
                    self.add_error("bundle", "This bundle has not been uploaded yet.")
            if policy and policy not in Rule.BUNDLE_POLICIES:
                self.add_error("policy", "Policy not allowed for bundles.")

        if policy and policy != Rule.BLOCKLIST:
            custom_msg = cleaned_data.get("custom_msg")
            if custom_msg:
                self.add_error("custom_msg", "Can only be set on BLOCKLIST rules")

        cleaned_data["target_type"] = target_type
        cleaned_data["target_sha256"] = target_sha256
        return cleaned_data

    def save(self):
        target, _ = Target.objects.get_or_create(type=self.cleaned_data["target_type"],
                                                 sha256=self.cleaned_data["target_sha256"])
        rule = Rule.objects.create(configuration=self.configuration,
                                   target=target,
                                   policy=self.cleaned_data["policy"],
                                   custom_msg=self.cleaned_data.get("custom_msg", ""),
                                   serial_numbers=self.cleaned_data.get("serial_numbers") or [],
                                   primary_users=self.cleaned_data.get("primary_users") or [])
        tags = self.cleaned_data.get("tags")
        if tags:
            rule.tags.set(tags)
        return rule


class UpdateRuleForm(forms.ModelForm):
    class Meta:
        model = Rule
        fields = ("policy", "custom_msg", "serial_numbers", "primary_users", "tags")

    def clean(self):
        cleaned_data = super().clean()
        target_type = cleaned_data.get("target_type")

        try:
            policy = int(cleaned_data.get("policy"))
        except (TypeError, ValueError):
            pass
        else:
            if target_type == Target.BUNDLE and policy not in Rule.BUNDLE_POLICIES:
                self.add_error("policy", "Policy not allowed for bundles.")
            if policy != Rule.BLOCKLIST:
                custom_msg = cleaned_data.get("custom_msg")
                if custom_msg:
                    self.add_error("custom_msg", "Can only be set on BLOCKLIST rules")

    def save(self, request):
        # to reverse changes made by the ModelForm validation
        self.instance.refresh_from_db()
        updates = {}
        updated = False
        # policy
        policy = self.cleaned_data["policy"]
        if self.instance.policy != policy:
            updates.setdefault("removed", {})["policy"] = translate_rule_policy(self.instance.policy)
            self.instance.policy = policy
            updated = True
            updates.setdefault("added", {})["policy"] = translate_rule_policy(self.instance.policy)
        # custom_msg
        custom_msg = self.cleaned_data["custom_msg"]
        if self.instance.custom_msg != custom_msg:
            if self.instance.custom_msg:
                updates.setdefault("removed", {})["custom_msg"] = self.instance.custom_msg
            self.instance.custom_msg = custom_msg
            self.instance.version = F("version") + 1  # bump version to trigger rule distribution
            updated = True
            if self.instance.custom_msg:
                updates.setdefault("added", {})["custom_msg"] = self.instance.custom_msg
        # serial_numbers
        serial_numbers = set(self.cleaned_data["serial_numbers"])
        old_serial_numbers = set(self.instance.serial_numbers)
        if serial_numbers != old_serial_numbers:
            self.instance.serial_numbers = self.cleaned_data["serial_numbers"]
            updated = True
            added_serial_numbers = serial_numbers - old_serial_numbers
            if added_serial_numbers:
                updates.setdefault("added", {})["serial_numbers"] = sorted(added_serial_numbers)
            removed_serial_numbers = old_serial_numbers - serial_numbers
            if removed_serial_numbers:
                updates.setdefault("removed", {})["serial_numbers"] = sorted(removed_serial_numbers)
        # primary_users
        primary_users = set(self.cleaned_data["primary_users"])
        old_primary_users = set(self.instance.primary_users)
        if primary_users != old_primary_users:
            self.instance.primary_users = self.cleaned_data["primary_users"]
            updated = True
            added_primary_users = primary_users - old_primary_users
            if added_primary_users:
                updates.setdefault("added", {})["primary_users"] = sorted(added_primary_users)
            removed_primary_users = old_primary_users - primary_users
            if removed_primary_users:
                updates.setdefault("removed", {})["primary_users"] = sorted(removed_primary_users)
        if updated:
            self.instance.save()
        # tags
        tags = set(self.cleaned_data["tags"])
        old_tags = set(self.instance.tags.all())
        if tags != old_tags:
            self.instance.tags.set(tags)
            added_tags = tags - old_tags
            if added_tags:
                updates.setdefault("added", {})["tags"] = [{"pk": t.pk, "name": t.name} for t in added_tags]
            removed_tags = old_tags - tags
            if removed_tags:
                updates.setdefault("removed", {})["tags"] = [{"pk": t.pk, "name": t.name} for t in removed_tags]
        # event
        if updates:
            rule_update_data = {"rule": self.instance.serialize_for_event(),
                                "result": "updated",
                                "updates": updates}
            transaction.on_commit(lambda: post_santa_rule_update_event(request, rule_update_data))

        return self.instance
