import json
import logging
import re
from dateutil import parser
from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.db import connection, transaction
from django.db.models import Count, F
from django.urls import reverse, NoReverseMatch
from zentral.conf import settings
from zentral.contrib.inventory.models import Tag
from .events import post_santa_rule_update_event
from .models import Configuration, Enrollment, Rule, RuleSet, Target, TargetState, VotingGroup


logger = logging.getLogger("zentral.contrib.santa.forms")


class TargetTypesWidget(forms.CheckboxSelectMultiple):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs, choices=Target.Type.choices)

    def format_value(self, value):
        if isinstance(value, str) and value:
            value = [v.strip() for v in value.split(",")]
        return super().format_value(value)


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'
        widgets = {
            "event_detail_url": forms.Textarea(attrs={"cols": "40", "rows": "3"}),
            "allowed_path_regex": forms.Textarea(attrs={"cols": "40", "rows": "3"}),
            "blocked_path_regex": forms.Textarea(attrs={"cols": "40", "rows": "3"}),
            "default_ballot_target_types": TargetTypesWidget,
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


class VotingGroupForm(forms.ModelForm):
    class Meta:
        model = VotingGroup
        fields = (
            "realm_group",
            "can_unflag_target",
            "can_mark_malware",
            "can_reset_target",
            "ballot_target_types",
            "voting_weight"
        )
        widgets = {"ballot_target_types": TargetTypesWidget}

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        super().__init__(*args, **kwargs)
        vg_rg_pks_to_exclude = [vg.realm_group.pk for vg in self.configuration.votinggroup_set.all()]
        if self.instance.pk and self.instance.realm_group.pk:
            # we allow the existing realm group of the voting group being updated
            vg_rg_pks_to_exclude.remove(self.instance.realm_group.pk)
        self.fields["realm_group"].queryset = self.fields["realm_group"].queryset.exclude(pk__in=vg_rg_pks_to_exclude)

    def save(self, *args, **kwargs):
        self.instance.configuration = self.configuration
        return super().save(*args, **kwargs)


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


class CDHashSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    query = forms.CharField(required=False,
                            widget=forms.TextInput(attrs={"placeholder": "cdhash",
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
        choices=[('', '...')] + Target.Type.rule_choices(),
        required=False,
    )
    policy = forms.ChoiceField(
        choices=[('', '...')] + Rule.Policy.rule_choices(),
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


def test_cdhash(cdhash):
    return re.match(r'^[a-f0-9]{40}\Z', cdhash) is not None


def test_sha256(sha256):
    return re.match(r'^[a-f0-9]{64}\Z', sha256) is not None


def test_signing_id_identifier(identifier):
    if ":" not in identifier:
        return False
    team_id, signing_id = identifier.split(":", 1)
    if not test_team_id(team_id) and team_id != "platform":
        return False
    return True


def test_team_id(team_id):
    return re.match(r'^[0-9A-Z]{10}\Z', team_id) is not None


def cleanup_target_identifier(target_type, identifier):
    if target_type == Target.Type.CDHASH:
        validator = test_cdhash
    elif target_type == Target.Type.SIGNING_ID:
        validator = test_signing_id_identifier
    elif target_type == Target.Type.TEAM_ID:
        identifier = identifier.upper()
        validator = test_team_id
    else:
        identifier = identifier.lower()
        validator = test_sha256
    if validator(identifier):
        return identifier


class RuleForm(RuleFormMixin, forms.Form):
    target_type = forms.ChoiceField(choices=Target.Type.rule_choices())
    target_identifier = forms.CharField()
    policy = forms.ChoiceField(choices=Rule.Policy.rule_choices())
    custom_msg = forms.CharField(label="Custom message", required=False,
                                 widget=forms.Textarea(attrs={"cols": "40", "rows": "2"}))
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"cols": "40", "rows": "2"}))
    serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    excluded_serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    primary_users = SimpleArrayField(forms.CharField(), required=False)
    excluded_primary_users = SimpleArrayField(forms.CharField(), required=False)
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    excluded_tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        self.binary = kwargs.pop("binary", None)
        self.cdhash = kwargs.pop("cdhash", None)
        self.certificate = kwargs.pop("certificate", None)
        self.team_id = kwargs.pop("team_id", None)
        self.signing_id = kwargs.pop("signing_id", None)
        super().__init__(*args, **kwargs)
        if (
            self.binary
            or self.cdhash
            or self.certificate
            or self.team_id
            or self.signing_id
        ):
            del self.fields["target_type"]
            del self.fields["target_identifier"]
        if not any(k == Rule.Policy.BLOCKLIST for k, _ in self.fields["policy"].choices):
            del self.fields["custom_msg"]

    def clean(self):
        cleaned_data = super().clean()
        if self.binary:
            target_type = Target.Type.BINARY
            target_identifier = self.binary.sha_256
        elif self.cdhash:
            target_type = Target.Type.CDHASH
            target_identifier = self.cdhash
        elif self.certificate:
            target_type = Target.Type.CERTIFICATE
            target_identifier = self.certificate.sha_256
        elif self.team_id:
            target_type = Target.Type.TEAM_ID
            target_identifier = self.team_id
        elif self.signing_id:
            target_type = Target.Type.SIGNING_ID
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
            if "target_identifier" in self.fields:
                error_field = "target_identifier"
            else:
                error_field = None
            target_identifier = cleanup_target_identifier(target_type, target_identifier)
            if target_identifier is None:
                self.add_error(error_field, f"Invalid {target_type} identifier")

        # policy
        try:
            policy = int(cleaned_data.get("policy"))
        except (TypeError, ValueError):
            pass

        # custom message only on blocklist rules
        if policy and policy != Rule.Policy.BLOCKLIST:
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
        widgets = {
            "custom_msg": forms.Textarea(attrs={"cols": "40", "rows": "2"}),
            "description": forms.Textarea(attrs={"cols": "40", "rows": "2"})
        }

    def clean(self):
        cleaned_data = super().clean()

        try:
            policy = int(cleaned_data.get("policy"))
        except (TypeError, ValueError):
            pass
        else:
            if policy != Rule.Policy.BLOCKLIST:
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
        policy = Rule.Policy(self.cleaned_data["policy"])
        instance_policy = Rule.Policy(self.instance.policy)
        if instance_policy != policy:
            updates.setdefault("removed", {})["policy"] = instance_policy.name
            self.instance.policy = policy
            updated = True
            updates.setdefault("added", {})["policy"] = self.instance.policy.name
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
            attrs={"autofocus": True, "size": 50}
        )
    )
    target_type = forms.ChoiceField(
        choices=[('', '…'),] + Target.Type.choices,
        required=False,
    )
    target_state = forms.ChoiceField(
        label="State",
        required=False,
        choices=[('', '…')] + TargetState.State.choices,
    )
    last_seen_days = forms.ChoiceField(
        label="Last seen",
        required=False,
        choices=[('', '…'),
                 ('1', '24 hours'),
                 ('3', '3 days'),
                 ('7', '7 days'),
                 ('14', '14 days'),
                 ('30', '30 days'),
                 ('90', '90 days')],
    )
    configuration = forms.ModelChoiceField(queryset=Configuration.objects.all(), empty_label="…")
    has_yes_votes = forms.BooleanField(label="Has upvotes")
    has_no_votes = forms.BooleanField(label="Has downvotes")
    todo = forms.BooleanField(label="Waiting for my ballot only", required=False, initial=False)
    order_by = forms.ChoiceField(
        label="Order by",
        required=False,
        choices=[('', '…'),
                 ('-last_seen', '↓ Last seen'),
                 ('-executed', '↓ Executed count'),
                 ('-blocked', '↓ Blocked count')]
    )

    @classmethod
    def search_query(
        cls,
        q=None,
        target_type=None,
        target_state=None,
        configuration_pk=None,
        has_yes_votes=None,
        has_no_votes=None,
        username=None,
        email=None,
        last_seen_days=None,
        order_by=None,
    ):
        if not target_type:
            target_type = None
        kwargs = {}
        # q
        if q:
            kwargs["q"] = "%{}%".format(connection.ops.prep_for_like_query(q))
            bi_where = ("where upper(f.name) like upper(%(q)s)"
                        " or upper(f.identifier) like upper(%(q)s)")
            ce_where = ("where upper(c.common_name) like upper(%(q)s)"
                        " or upper(c.organizational_unit) like upper(%(q)s)"
                        " or upper(c.sha_256) like upper(%(q)s)")
            ti_where = ("where upper(f.name) like upper(%(q)s)"
                        " or upper(f.team_id) like upper(%(q)s)"
                        " or upper(c.organization) like upper(%(q)s)")
            ch_where = ("where upper(f.name) like upper(%(q)s)"
                        " or upper(f.cdhash) like upper(%(q)s)")
            si_where = ("where upper(f.name) like upper(%(q)s)"
                        " or upper(f.signing_id) like upper(%(q)s)")
            bu_where = ("where upper(b.name) like upper(%(q)s)"
                        " or upper(t.identifier) like upper(%(q)s)")
            mbu_where = ("where upper(b.name) like upper(%(q)s)"
                         " or upper(t.identifier) like upper(%(q)s)")
        else:
            bi_where = ce_where = bu_where = mbu_where = ""
            ti_where = "where f.team_id IS NOT NULL"
            ch_where = "where (f.cdhash = '') IS FALSE"
            si_where = "where (f.signing_id = '') IS FALSE"
        wheres = []
        havings = []
        # target state
        if target_state is not None:
            wheres.append("coalesce(ts.state, 0) = %(target_state)s")
            kwargs["target_state"] = target_state
        # configuration
        if configuration_pk:
            ac_cfg_where = "where tc.configuration_id = %(configuration_pk)s"
            wheres.append("(ac.configuration_id = %(configuration_pk)s "
                          " or ts.configuration_id = %(configuration_pk)s)")
            kwargs["configuration_pk"] = configuration_pk
        else:
            ac_cfg_where = ""
        # votes?
        if has_yes_votes or has_no_votes:
            votes_where = ""
            if configuration_pk:
                votes_where = "and hvv.configuration_id = %(configuration_pk)s"
            if has_yes_votes != has_no_votes:
                if has_yes_votes:
                    votes_where = f"{votes_where} and hvv.was_yes_vote = 't'"
                elif has_no_votes:
                    votes_where = f"{votes_where} and hvv.was_yes_vote = 'f'"
            wheres.append(
                "exists ("
                "  select * from santa_vote hvv"
                "  join santa_ballot hvb on (hvv.ballot_id = hvb.id)"
                "  where hvb.target_id = t.id"
                f" {votes_where}"
                ")"
            )
        # no votes from user
        if username or email:
            todo_cfg_where = "and (nets.reset_at is null or nets.reset_at < nev.created_at)"
            if configuration_pk:
                todo_cfg_where = f"{todo_cfg_where} and nev.configuration_id = %(configuration_pk)s"
            wheres.append(
                "not exists ("
                "  select * from santa_vote nev"
                "  join santa_ballot neb on (nev.ballot_id = neb.id)"
                "  left join santa_targetstate nets on ("
                "    neb.target_id = nets.target_id"
                "    and nev.configuration_id = nets.configuration_id"
                "  )"
                "  left join realms_realmuser neu on (neb.realm_user_id = neu.uuid)"
                "  where neb.target_id = t.id and neb.replaced_by_id is null"
                "  and (neb.user_uid = %(username)s or neu.username = %(username)s"
                "       or neb.user_uid = %(email)s or neu.username = %(email)s)"
                f" {todo_cfg_where}"
                ")"
            )
            kwargs["username"] = username
            kwargs["email"] = email
        if last_seen_days is not None:
            havings.append(
                "(max(ac.last_seen) is not null and max(ac.last_seen) > now() - interval '%(last_seen_days)s days')"
            )
            kwargs["last_seen_days"] = last_seen_days
        # serialize wheres & havings
        if wheres:
            where = "where " + " and ".join(wheres)
        else:
            where = ""
        if havings:
            having = "having " + " and ".join(havings)
        else:
            having = ""

        targets_subqueries = {
            "BINARY":
                "select 'BINARY' as target_type,  f.identifier, f.name as sort_str,"
                "jsonb_build_object("
                " 'name', f.name,"
                " 'cert_cn', c.common_name,"
                " 'cert_sha256', c.sha_256,"
                " 'cert_ou', c.organizational_unit"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{bi_where} "
                "group by target_type, f.identifier, f.name, c.common_name, c.sha_256, c.organizational_unit",
            "CERTIFICATE":
                "select 'CERTIFICATE' as target_type, c.sha_256 as identifier, c.common_name as sort_str,"
                "jsonb_build_object("
                " 'cn', c.common_name,"
                " 'ou', c.organizational_unit,"
                " 'valid_from', c.valid_from,"
                " 'valid_until', c.valid_until"
                ") as object "
                "from inventory_certificate as c "
                "join collected_files as f on (c.id = f.signed_by_id) "
                f"{ce_where} "
                "group by target_type, c.sha_256, c.common_name, c.organizational_unit, c.valid_from, c.valid_until",
            "TEAMID":
                "select 'TEAMID' as target_type, f.team_id as identifier, f.team_id as sort_str,"
                "jsonb_build_object("
                " 'organizational_units', jsonb_agg(c.organizational_unit),"
                " 'organizations', jsonb_agg(c.organization)"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on "
                "(f.signed_by_id = c.id and f.team_id = c.organizational_unit) "
                f"{ti_where} "
                "group by target_type, f.team_id",
            "CDHASH":
                "select 'CDHASH' as target_type, f.cdhash as identifier, f.cdhash as sort_str,"
                "jsonb_build_object("
                " 'file_names', jsonb_agg(distinct f.name),"
                " 'cert_cns', jsonb_agg(distinct c.common_name)"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{ch_where} "
                "group by target_type, f.cdhash",
            "SIGNINGID":
                "select 'SIGNINGID' as target_type, f.signing_id as identifier, f.signing_id as sort_str,"
                "jsonb_build_object("
                " 'file_names', jsonb_agg(distinct f.name),"
                " 'cert_cns', jsonb_agg(distinct c.common_name)"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{si_where} "
                "group by target_type, f.signing_id",
            "BUNDLE":
                "select 'BUNDLE' as target_type, t.identifier, b.name as sort_str,"
                "jsonb_build_object("
                " 'name', b.name,"
                " 'version', b.version,"
                " 'version_str', b.version_str"
                ") as object "
                "from santa_bundle as b "
                "join santa_target as t on (b.target_id = t.id) "
                f"{bu_where}",
            "METABUNDLE":
                "select 'METABUNDLE' as target_type, t.identifier, max(b.name) as sort_str,"
                "jsonb_build_object("
                " 'names', jsonb_agg(b.name)"
                ") as object "
                "from santa_metabundle as mb "
                "join santa_target as t on (mb.target_id = t.id) "
                "left join santa_bundle as b on (b.metabundle_id = mb.id) "
                f"{mbu_where} "
                "group by target_type, t.identifier"
        }
        targets_query = " union ".join(v for k, v in targets_subqueries.items()
                                       if target_type is None or k == target_type)
        if order_by == "-last_seen":
            primary_order_by = "max(ac.last_seen) desc,"
        elif order_by == "-executed":
            primary_order_by = "coalesce(sum(ac.executed_count), 0) desc,"
        elif order_by == "-blocked":
            primary_order_by = "coalesce(sum(ac.blocked_count), 0) desc,"
        else:
            if order_by:
                logger.error("Unknown order by value: %s", order_by)
            primary_order_by = ""
        query = (
            "with collected_files as ("
            "  select f.sha_256 as identifier, f.cdhash, f.signed_by_id, f.signing_id, f.name,"
            "  case when (signing_id = '') is false and not starts_with(signing_id, 'platform') "
            "  then split_part(signing_id, ':', 1) else null end team_id"
            "  from inventory_file as f"
            "  join inventory_source as s on (f.source_id = s.id)"
            "  where s.module='zentral.contrib.santa' and s.name = 'Santa events'"
            "  group by f.sha_256, f.cdhash, f.signed_by_id, f.signing_id, f.name"
            "), targets_info as ("
            f" {targets_query}"
            "), targets as ("
            "  select t.id, t.type target_type, t.identifier, ti.sort_str, ti.object"
            "  from targets_info ti"
            "  join santa_target t on (t.type = ti.target_type and t.identifier = ti.identifier)"
            "), all_counters as ("
            #  direct counters
            "  select tc.target_id, tc.configuration_id,"
            "  tc.blocked_count, tc.collected_count, tc.executed_count, tc.updated_at last_seen"
            "  from santa_targetcounter tc"
            f" {ac_cfg_where}"
            #  aggregated metabundle counters
            "  union"
            "  select mb.target_id, tc.configuration_id,"
            "  sum(tc.blocked_count) blocked_count,"
            "  sum(tc.collected_count) collected_count,"
            "  sum(tc.executed_count) executed_count,"
            "  max(tc.updated_at) last_seen"
            "  from santa_metabundle mb"
            "  join santa_bundle b on (b.metabundle_id = mb.id)"
            "  join santa_targetcounter tc on (tc.target_id = b.target_id)"
            f" {ac_cfg_where}"
            "  group by mb.target_id, tc.configuration_id"
            ") "
            "select t.id, t.target_type, t.identifier, t.object, count(*) over() as full_count,"
            # counters
            "coalesce(sum(ac.blocked_count), 0) blocked_count,"
            "coalesce(sum(ac.collected_count), 0) collected_count,"
            "coalesce(sum(ac.executed_count), 0) executed_count,"
            "max(ac.last_seen) last_seen,"
            # states
            "coalesce(max(ts.state), 0) max_state,"
            "coalesce(min(ts.state), 0) min_state,"
            "coalesce(max(ts.score), 0) max_score,"
            "coalesce(min(ts.score), 0) min_score,"
            "min(ts.updated_at) min_state_updated_at,"
            "max(ts.updated_at) max_state_updated_at,"
            # rules
            "(select count(*) from santa_rule r where r.target_id = t.id) rule_count "
            "from targets t "
            "left join all_counters ac on (ac.target_id = t.id) "
            "left join santa_targetstate ts on (ts.target_id = t.id) "
            f"{where} "
            "group by t.id, t.target_type, t.identifier, t.object, t.sort_str "
            f"{having} "
            f"order by {primary_order_by} t.sort_str, t.identifier "
        )
        return query, kwargs

    def search_query_kwargs(self, current_username, current_email):
        kwargs = {}
        q = self.cleaned_data.get("q")
        if q:
            kwargs["q"] = q
        target_type = self.cleaned_data.get("target_type")
        if target_type:
            kwargs["target_type"] = target_type
        target_state = self.cleaned_data.get("target_state")
        if target_state != "":
            kwargs["target_state"] = int(target_state)
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            kwargs["configuration_pk"] = configuration.pk
        has_yes_votes = self.cleaned_data.get("has_yes_votes")
        if has_yes_votes:
            kwargs["has_yes_votes"] = has_yes_votes
        has_no_votes = self.cleaned_data.get("has_no_votes")
        if has_no_votes:
            kwargs["has_no_votes"] = has_no_votes
        todo = self.cleaned_data.get("todo")
        if todo and (current_username or current_email):
            if current_username:
                kwargs["username"] = current_username
            if current_email:
                kwargs["email"] = current_email
        try:
            kwargs["last_seen_days"] = min(366, max(1, int(self.cleaned_data.get("last_seen_days"))))
        except (ValueError, TypeError):
            pass
        order_by = self.cleaned_data.get("order_by")
        if order_by:
            kwargs["order_by"] = order_by
        return kwargs

    def results(self, current_username, current_email, offset, limit):
        query, kwargs = self.search_query(**self.search_query_kwargs(current_username, current_email))
        kwargs.update({"offset": offset, "limit": limit})
        with connection.cursor() as cursor:
            cursor.execute(f"{query} offset %(offset)s limit %(limit)s", kwargs)
            columns = [col[0] for col in cursor.description]
            results = []
            for row in cursor.fetchall():
                result = dict(zip(columns, row))
                row_obj = json.loads(result.pop("object"))
                obj = {}
                for key, val in row_obj.items():
                    if key in ("valid_from", "valid_until"):
                        val = parser.parse(val)
                    elif isinstance(val, list):
                        val = sorted(set(i for i in val if i is not None))
                    obj[key] = val
                result["object"] = obj
                result["target_type"] = target_type = Target.Type(result.pop("target_type"))
                result["target_type_for_display"] = target_type.label
                try:
                    result["url"] = reverse(target_type.url_name, args=(result["identifier"],))
                except NoReverseMatch:
                    logger.error("Could not file target URL. Bad %s identifier? '%s'",
                                 target_type, result["identifier"])
                result["min_state"] = TargetState.State(result.pop("min_state"))
                result["max_state"] = TargetState.State(result.pop("max_state"))
                results.append(result)
        return results


class BallotSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    target_type = forms.ChoiceField(
        label="Type",
        choices=[('', '…'),] + Target.Type.choices,
        required=False,
    )
    target_identifier = forms.CharField(
        label="Identifier",
        required=False,
        widget=forms.TextInput(attrs={"size": 50})
    )
    target_state = forms.ChoiceField(
        label="State",
        required=False,
        choices=[('', '…')] + TargetState.State.choices,
    )
    configuration = forms.ModelChoiceField(queryset=Configuration.objects.all(), empty_label="…")
    realm_user = forms.CharField(label="User", required=False)
    include_yes_votes = forms.BooleanField(label="Yes votes", required=False, initial=False)
    include_no_votes = forms.BooleanField(label="No votes", required=False, initial=False)
    include_revised_ballots = forms.BooleanField(label="Revised ballots", required=False, initial=False)
    include_reset_ballots = forms.BooleanField(label="Reset ballots", required=False, initial=False)
    todo = forms.BooleanField(label="Waiting for my ballot only", required=False, initial=False)

    def results(self, current_username, current_email, offset, limit):
        where_list = ["(et.identifier is null or (s.module = 'zentral.contrib.santa' and s.name = 'Santa events'))",]
        having_list = []
        kwargs = {"offset": offset, "limit": limit}
        target_type = self.cleaned_data.get("target_type")
        if target_type:
            where_list.append("t.type = %(target_type)s")
            kwargs["target_type"] = target_type
        target_identifier = self.cleaned_data.get("target_identifier")
        if target_identifier:
            where_list.append("t.identifier = %(target_identifier)s")
            kwargs["target_identifier"] = target_identifier
        target_state = self.cleaned_data.get("target_state")
        if target_state != "":
            where_list.append("coalesce(ts.state, 0) = %(target_state)s")
            kwargs["target_state"] = target_state
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            where_list.append("v.configuration_id = %(configuration_pk)s")
            kwargs["configuration_pk"] = configuration.pk
        realm_user = self.cleaned_data.get("realm_user")
        if realm_user:
            where_list.append("(b.user_uid = %(realm_user)s or u.username = %(realm_user)s)")
            kwargs["realm_user"] = realm_user
        include_yes_votes = self.cleaned_data.get("include_yes_votes", False)
        include_no_votes = self.cleaned_data.get("include_no_votes", False)
        if include_yes_votes != include_no_votes:
            if include_yes_votes:
                having_list.append("bool_or(coalesce(v.was_yes_vote, 'f')) = 't'")
            else:
                having_list.append("bool_or(coalesce(not v.was_yes_vote, 'f')) = 't'")
        include_revised_ballots = self.cleaned_data.get("include_revised_ballots")
        if not include_revised_ballots:
            where_list.append("b.replaced_by_id is null")
        include_reset_ballots = self.cleaned_data.get("include_reset_ballots")
        if not include_reset_ballots:
            where_list.append("(ts.reset_at is null or v.created_at is null or v.created_at > ts.reset_at)")
        todo = self.cleaned_data.get("todo")
        if todo:
            todo_cfg_where = "and (nets.reset_at is null or nets.reset_at < nev.created_at)"
            if configuration:
                todo_cfg_where = f"{todo_cfg_where} and nev.configuration_id = %(configuration_pk)s"
            where_list.append(
                "not exists ("
                "  select * from santa_vote nev"
                "  join santa_ballot neb on (nev.ballot_id = neb.id)"
                "  join santa_targetstate nets on ("
                "    neb.target_id = nets.target_id"
                "    and nev.configuration_id = nets.configuration_id"
                "  )"
                "  left join realms_realmuser neu on (neb.realm_user_id = neu.uuid)"
                "  where neb.target_id = t.id and neb.replaced_by_id is null"
                "  and (neb.user_uid = %(current_username)s or neu.username = %(current_username)s"
                "       or neb.user_uid = %(current_email)s or neu.username = %(current_email)s)"
                f" {todo_cfg_where}"
                ")"
            )
            kwargs["current_username"] = current_username
            kwargs["current_email"] = current_email
        wheres = " and ".join(where_list)
        if wheres:
            wheres = f"where {wheres} "
        havings = " and ".join(having_list)
        if havings:
            havings = f"having {havings} "
        query = (
            "select b.id, b.created_at, b.target_id, b.replaced_by_id,"
            "t.type target_type, t.identifier target_identifier,"
            "et.identifier event_target_identifier, max(f.name) filename,"
            "coalesce(ts.state, 0) target_state,"
            "b.user_uid, u.uuid realmuser_id, u.username realmuser_username,"
            "bool_or(coalesce(v.was_yes_vote, 'f')) has_yes_votes,"
            "bool_or(coalesce(not v.was_yes_vote, 'f')) has_no_votes,"
            "jsonb_agg("
            "  distinct jsonb_build_object("
            "    'cfg_name', c.name,"
            "    'cfg_pk', c.id,"
            "    'yes_vote', v.was_yes_vote,"
            "    'weight', v.weight,"
            "    'reset', ts.reset_at is not null and v.created_at is not null and ts.reset_at > v.created_at"
            "  )"
            ") votes, "
            "count(*) over() full_count "
            "from santa_ballot b "
            "join santa_target t on (b.target_id = t.id) "
            "left join santa_target et on (b.event_target_id = et.id) "
            "left join realms_realmuser u on (b.realm_user_id = u.uuid) "
            "left join santa_vote v on (v.ballot_id = b.id) "
            "left join santa_configuration c on (v.configuration_id = c.id) "
            "left join santa_targetstate ts on (ts.configuration_id = c.id and ts.target_id = t.id) "
            "left join inventory_file f on (f.sha_256 = et.identifier) "
            "left join inventory_source s on (f.source_id = s.id) "
            f"{wheres}"
            "group by b.id, b.created_at, b.target_id, b.replaced_by_id,"
            "t.type, t.identifier, et.identifier,"
            "ts.state,"
            "b.user_uid, u.uuid, u.username "
            f"{havings}"
            "order by b.created_at desc offset %(offset)s limit %(limit)s"
        )
        results = []
        targets = {}
        with connection.cursor() as cursor:
            cursor.execute(query, kwargs)
            columns = [col[0] for col in cursor.description]
            for idx, row in enumerate(cursor.fetchall()):
                # result
                result = dict(zip(columns, row))
                result["votes"] = [v for v in json.loads(result.pop("votes")) if v["cfg_pk"] is not None]
                result["target_type"] = Target.Type(result.pop("target_type"))
                result["target_url"] = reverse(result["target_type"].url_name,
                                               args=(result["target_identifier"],))
                if result["event_target_identifier"]:
                    result["event_target_url"] = reverse(Target.Type.BINARY.url_name,
                                                         args=(result["event_target_identifier"],))
                results.append(result)
                # target keys
                ballot_target_key = (result["target_type"], result["target_identifier"])
                targets.setdefault(ballot_target_key, []).append(idx)

        for key, display_str in Target.objects.get_targets_display_strings(targets.keys()).items():
            for idx in targets[key]:
                results[idx]["target_display_str"] = display_str

        return results


class AdminVoteForm(forms.Form):
    yes_no = forms.ChoiceField(choices=[], required=True)

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration")
        kwargs["prefix"] = f"cfg-{self.configuration.pk}"
        allowed_votes = kwargs.pop("allowed_votes")
        super().__init__(*args, **kwargs)
        choices = [("NOVOTE", "No vote")]
        for yes_no in allowed_votes:
            if yes_no is True:
                choices.append(("YES", "Upvote"))
            if yes_no is False:
                choices.append(("NO", "Downvote"))
        self.fields["yes_no"].choices = choices

    def get_vote(self):
        yes_no = self.cleaned_data.get("yes_no")
        if yes_no == "YES":
            return (self.configuration, True)
        elif yes_no == "NO":
            return (self.configuration, False)
        return None
