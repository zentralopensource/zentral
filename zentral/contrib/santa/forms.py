import re
from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.db import transaction
from django.db.models import Count, F
from zentral.conf import settings
from zentral.contrib.inventory.models import Tag
from .events import post_santa_rule_update_event
from .models import Bundle, Configuration, Enrollment, Rule, RuleSet, Target, translate_rule_policy


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'
        widgets = {
            "event_detail_url": forms.Textarea(attrs={"cols": "40", "rows": "3"}),
            "allowed_path_regex": forms.Textarea(attrs={"cols": "40", "rows": "3"}),
            "blocked_path_regex": forms.Textarea(attrs={"cols": "40", "rows": "3"})
        }

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

        # block USB
        block_usb_mount = cleaned_data.get("block_usb_mount")
        remount_usb_mode = cleaned_data.get("remount_usb_mode")
        if remount_usb_mode and not block_usb_mount:
            self.add_error(
                "remount_usb_mode",
                "'Block USB mount' must be set to use this option"
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
        self.standalone = kwargs.pop("standalone", False)
        super().__init__(*args, **kwargs)
        # hide configuration dropdown if configuration if fixed
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()


class BinarySearchForm(forms.Form):
    template_name = "django/forms/search.html"

    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "name",
                                                         "size": 50}))


class BundleSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    name = forms.CharField(label="Name", required=False,
                           widget=forms.TextInput(attrs={"placeholder": "bundle name, ID",
                                                         "size": 50}))


class CertificateSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "common name, organization",
                                                          "size": 50}))


class TeamIDSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "team ID, organization",
                                                          "size": 50}))


class SigningIDSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "signing ID",
                                                          "size": 50}))


class RuleSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    ruleset = forms.ModelChoiceField(
        queryset=RuleSet.objects.all(),
        required=False,
        empty_label='...',
    )
    target_type = forms.ChoiceField(
        choices=(('', '...'),) + Target.TYPE_CHOICES,
        required=False,
    )
    policy = forms.ChoiceField(
        choices=(('', '...'),) + Rule.POLICY_CHOICES,
        required=False,
    )
    identifier = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "autofocus": True,
                "size": 32,
            }
        ),
    )

    field_order = ['identifier', 'policy', 'ruleset', 'target_type']

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
        identifier = self.cleaned_data.get("identifier")
        if identifier:
            qs = qs.filter(target__identifier__icontains=identifier)
        return qs


class RuleFormMixin:
    def validate_scope(self):
        # primary user conflicts
        primary_user_conflicts = ", ".join(f"'{u}'" for u in self.cleaned_data["primary_users"]
                                           if u in self.cleaned_data["excluded_primary_users"])
        if primary_user_conflicts:
            self.add_error(
                "excluded_primary_users",
                f"{primary_user_conflicts} both included and excluded"
            )

        # serial number conflicts
        serial_number_conflicts = ", ".join(f"'{sn}'" for sn in self.cleaned_data["serial_numbers"]
                                            if sn in self.cleaned_data["excluded_serial_numbers"])
        if serial_number_conflicts:
            self.add_error(
                "excluded_serial_numbers",
                f"{serial_number_conflicts} both included and excluded"
            )

        # tag conflicts
        tag_conflicts = ", ".join(f"'{t.name}'" for t in self.cleaned_data["tags"]
                                  if t in self.cleaned_data["excluded_tags"])
        if tag_conflicts:
            self.add_error(
                "excluded_tags",
                f"{tag_conflicts} both included and excluded"
            )


def test_sha256(sha256):
    return re.match(r'^[a-f0-9]{64}\Z', sha256) is not None


def test_signing_id_identifier(identifier):
    if ":" not in identifier:
        return False
    team_id, signing_id = identifier.split(":", 1)
    if not test_team_id(team_id) and team_id != "platform":
        return False
    return re.match(r'^([0-9a-zA-Z_\-]+\.)*([0-9a-zA-Z_\-]+)\Z', signing_id) is not None


def test_team_id(team_id):
    return re.match(r'^[0-9A-Z]{10}\Z', team_id) is not None


class RuleForm(RuleFormMixin, forms.Form):
    target_type = forms.ChoiceField(choices=Target.TYPE_CHOICES)
    target_identifier = forms.CharField()
    policy = forms.ChoiceField(choices=Rule.POLICY_CHOICES)
    custom_msg = forms.CharField(label="Custom message", required=False,
                                 widget=forms.Textarea(attrs={"cols": "40", "rows": "10"}))
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"cols": "40", "rows": "10"}))
    serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    excluded_serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    primary_users = SimpleArrayField(forms.CharField(), required=False)
    excluded_primary_users = SimpleArrayField(forms.CharField(), required=False)
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    excluded_tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        self.binary = kwargs.pop("binary", None)
        self.bundle = kwargs.pop("bundle", None)
        self.certificate = kwargs.pop("certificate", None)
        self.team_id = kwargs.pop("team_id", None)
        self.signing_id = kwargs.pop("signing_id", None)
        super().__init__(*args, **kwargs)
        if self.binary or self.bundle or self.certificate or self.team_id or self.signing_id:
            del self.fields["target_type"]
            del self.fields["target_identifier"]
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
            target_identifier = self.binary.sha_256
        elif self.bundle:
            target_type = Target.BUNDLE
            target_identifier = self.bundle.target.identifier
        elif self.certificate:
            target_type = Target.CERTIFICATE
            target_identifier = self.certificate.sha_256
        elif self.team_id:
            target_type = Target.TEAM_ID
            target_identifier = self.team_id
        elif self.signing_id:
            target_type = Target.SIGNING_ID
            target_identifier = self.signing_id
        else:
            target_type = cleaned_data.get("target_type")
            target_identifier = cleaned_data.get("target_identifier")

        # duplicated rule
        if target_type and target_identifier and Rule.objects.filter(configuration=self.configuration,
                                                                     target__type=target_type,
                                                                     target__identifier=target_identifier).count():
            self.add_error(None, "A rule for this target already exists")

        # identifier
        if target_identifier:
            if target_type == Target.SIGNING_ID:
                if not test_signing_id_identifier(target_identifier):
                    self.add_error("target_identifier", "Invalid Signing ID target identifier")
            elif target_type == Target.TEAM_ID:
                target_identifier = target_identifier.upper()
                if not test_team_id(target_identifier):
                    self.add_error("target_identifier", "Invalid Team ID")
            else:
                target_identifier = target_identifier.lower()
                if not test_sha256(target_identifier):
                    self.add_error("target_identifier", "Invalid sha256")

        # policy
        try:
            policy = int(cleaned_data.get("policy"))
        except (TypeError, ValueError):
            pass

        # bundle target checks
        if target_type == Target.BUNDLE:
            try:
                bundle = Bundle.objects.get(target__identifier=target_identifier)
            except Bundle.DoesNotExist:
                self.add_error("bundle", 'Unknown bundle.')
            else:
                if not bundle.uploaded_at:
                    self.add_error("bundle", "This bundle has not been uploaded yet.")
            if policy and policy not in Rule.BUNDLE_POLICIES:
                self.add_error("policy", "Policy not allowed for bundles.")

        # custom message only on blocklist rules
        if policy and policy != Rule.BLOCKLIST:
            custom_msg = cleaned_data.get("custom_msg")
            if custom_msg:
                self.add_error("custom_msg", "Can only be set on BLOCKLIST rules")

        cleaned_data["target_type"] = target_type
        cleaned_data["target_identifier"] = target_identifier

        self.validate_scope()
        return cleaned_data

    def save(self):
        target, _ = Target.objects.get_or_create(type=self.cleaned_data["target_type"],
                                                 identifier=self.cleaned_data["target_identifier"])
        rule = Rule.objects.create(configuration=self.configuration,
                                   target=target,
                                   policy=self.cleaned_data["policy"],
                                   custom_msg=self.cleaned_data.get("custom_msg", ""),
                                   description=self.cleaned_data.get("description", ""),
                                   serial_numbers=self.cleaned_data.get("serial_numbers") or [],
                                   excluded_serial_numbers=self.cleaned_data.get("excluded_serial_numbers") or [],
                                   primary_users=self.cleaned_data.get("primary_users") or [],
                                   excluded_primary_users=self.cleaned_data.get("excluded_primary_users") or [])
        tags = self.cleaned_data.get("tags")
        if tags:
            rule.tags.set(tags)
        excluded_tags = self.cleaned_data.get("excluded_tags")
        if excluded_tags:
            rule.excluded_tags.set(excluded_tags)
        return rule


class UpdateRuleForm(RuleFormMixin, forms.ModelForm):
    class Meta:
        model = Rule
        fields = ("policy", "custom_msg", "description",
                  "serial_numbers", "excluded_serial_numbers",
                  "primary_users", "excluded_primary_users",
                  "tags", "excluded_tags")

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

        self.validate_scope()

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
        # description
        description = self.cleaned_data["description"]
        if self.instance.description != description:
            if self.instance.description:
                updates.setdefault("removed", {})["description"] = self.instance.description
            self.instance.description = description
            updated = True
            if self.instance.description:
                updates.setdefault("added", {})["description"] = self.instance.description
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
        # excluded_serial_numbers
        excluded_serial_numbers = set(self.cleaned_data["excluded_serial_numbers"])
        old_excluded_serial_numbers = set(self.instance.excluded_serial_numbers)
        if excluded_serial_numbers != old_excluded_serial_numbers:
            self.instance.excluded_serial_numbers = self.cleaned_data["excluded_serial_numbers"]
            updated = True
            added_excluded_serial_numbers = excluded_serial_numbers - old_excluded_serial_numbers
            if added_excluded_serial_numbers:
                updates.setdefault("added", {})["excluded_serial_numbers"] = sorted(added_excluded_serial_numbers)
            removed_excluded_serial_numbers = old_excluded_serial_numbers - excluded_serial_numbers
            if removed_excluded_serial_numbers:
                updates.setdefault("removed", {})["excluded_serial_numbers"] = sorted(removed_excluded_serial_numbers)
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
        # excluded_primary_users
        excluded_primary_users = set(self.cleaned_data["excluded_primary_users"])
        old_excluded_primary_users = set(self.instance.excluded_primary_users)
        if excluded_primary_users != old_excluded_primary_users:
            self.instance.excluded_primary_users = self.cleaned_data["excluded_primary_users"]
            updated = True
            added_excluded_primary_users = excluded_primary_users - old_excluded_primary_users
            if added_excluded_primary_users:
                updates.setdefault("added", {})["excluded_primary_users"] = sorted(added_excluded_primary_users)
            removed_excluded_primary_users = old_excluded_primary_users - excluded_primary_users
            if removed_excluded_primary_users:
                updates.setdefault("removed", {})["excluded_primary_users"] = sorted(removed_excluded_primary_users)
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
        # excluded_tags
        excluded_tags = set(self.cleaned_data["excluded_tags"])
        old_excluded_tags = set(self.instance.excluded_tags.all())
        if excluded_tags != old_excluded_tags:
            self.instance.excluded_tags.set(excluded_tags)
            added_excluded_tags = excluded_tags - old_excluded_tags
            if added_excluded_tags:
                updates.setdefault("added", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                    for t in added_excluded_tags]
            removed_excluded_tags = old_excluded_tags - excluded_tags
            if removed_excluded_tags:
                updates.setdefault("removed", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                      for t in removed_excluded_tags]
        # event
        if updates:
            rule_update_data = {"rule": self.instance.serialize_for_event(),
                                "result": "updated",
                                "updates": updates}
            transaction.on_commit(lambda: post_santa_rule_update_event(request, rule_update_data))

        return self.instance


class TargetSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label='SHA256, Name, …',
        required=False,
        widget=forms.TextInput(
            attrs={"autofocus": True,
                   "size": 32,
                   }
        )
    )
    target_type = forms.ChoiceField(
        choices=(('', '...'),) + Target.TYPE_CHOICES,
        required=False,
    )
