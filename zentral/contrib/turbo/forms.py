from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.db.models import F, Q, TextField
from django.db.models.functions import Coalesce

from zentral.contrib.inventory.models import Tag
from .compliance_checks import sync_mscp_check_compliance_check, sync_script_compliance_check
from .models import (Configuration, EnrolledMachine, Enrollment, Job, MSCPCheck, OneTimeJob,
                     RecurringJob, Script)


class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = "__all__"
        widgets = {
            "description": forms.Textarea(attrs={"rows": "2"}),
        }


class EnrollmentForm(forms.ModelForm):
    class Meta:
        model = Enrollment
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        kwargs.pop("enrollment_only", None)
        kwargs.pop("standalone", None)
        super().__init__(*args, **kwargs)
        if self.configuration:
            self.fields["configuration"].widget = forms.HiddenInput()


class ScriptForm(forms.ModelForm):
    compliance_check = forms.BooleanField(label="Compliance check", required=False)
    # keep the tagging / compliance roles grouped after the definition & compatibility fields
    field_order = ["name", "description", "source",
                   "arch_amd64", "arch_arm64", "min_os_version", "max_os_version",
                   "tag", "compliance_check"]

    class Meta:
        model = Script
        fields = "__all__"
        widgets = {
            "description": forms.Textarea(attrs={"rows": "2"}),
            "source": forms.Textarea(attrs={"rows": "10"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["compliance_check"].initial = self.instance.compliance_check is not None

    def clean(self):
        super().clean()
        if not self.cleaned_data.get("arch_amd64") and not self.cleaned_data.get("arch_arm64"):
            msg = "Select at least one architecture"
            self.add_error("arch_amd64", msg)
            self.add_error("arch_arm64", msg)

    def save(self, *args, **kwargs):
        # version is on the Job; a source change bumps it (osquery bumps Query.version on sql change).
        # NB: UUID PK default fills pk at construction, so use _state.adding (not pk) for create-vs-update.
        bump = not self.instance._state.adding and "source" in self.changed_data
        script = super().save(*args, **kwargs)   # Script.save() mints the Job on create
        if bump:
            script.job.bump_version()
        sync_script_compliance_check(script, self.cleaned_data.get("compliance_check"))
        return script


class ScriptSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label="Name or source", required=False,
        widget=forms.TextInput(attrs={"autofocus": True, "size": 36}),
    )
    configuration = forms.ModelChoiceField(
        label="Scheduled in", queryset=Configuration.objects.all(), required=False, empty_label="...",
    )

    def get_queryset(self):
        qs = Script.objects.select_related("job", "compliance_check", "tag").order_by("name")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(name__icontains=q) | Q(source__icontains=q))
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            qs = qs.filter(
                Q(job__recurringjob__configuration=configuration)
                | Q(job__onetimejob__configuration=configuration)
            ).distinct()
        return qs


class MSCPCheckForm(forms.ModelForm):
    class Meta:
        model = MSCPCheck
        fields = ("rule_id", "baseline", "odv_int", "odv_string", "odv_bool")
        widgets = {
            "rule_id": forms.TextInput(),
            "odv_string": forms.TextInput(),
        }

    def clean_odv_string(self):
        # an empty override is no override (defer to the baseline default), not the empty string
        return self.cleaned_data.get("odv_string") or None

    def clean(self):
        super().clean()
        set_odvs = [f for f in ("odv_int", "odv_string", "odv_bool") if self.cleaned_data.get(f) is not None]
        if len(set_odvs) > 1:
            for f in set_odvs:
                self.add_error(f, "Set at most one ODV override")
        if set_odvs and self.cleaned_data.get("baseline"):
            self.add_error("baseline", "Set a baseline or an ODV override, not both")

    def save(self, *args, **kwargs):
        # every MSCPCheck field is identity-bearing, so any change bumps the Job version and re-syncs the CC.
        bump = not self.instance._state.adding and bool(self.changed_data)
        mscp_check = super().save(*args, **kwargs)   # MSCPCheck.save() mints the Job + the CC on create
        if bump:
            mscp_check.job.bump_version()
        sync_mscp_check_compliance_check(mscp_check)
        return mscp_check


class MSCPCheckSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label="Rule or baseline", required=False,
        widget=forms.TextInput(attrs={"autofocus": True, "size": 36}),
    )
    configuration = forms.ModelChoiceField(
        label="Scheduled in", queryset=Configuration.objects.all(), required=False, empty_label="...",
    )

    def get_queryset(self):
        qs = MSCPCheck.objects.select_related("job", "compliance_check").order_by("rule_id", "baseline")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(rule_id__icontains=q) | Q(baseline__icontains=q))
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            qs = qs.filter(
                Q(job__recurringjob__configuration=configuration)
                | Q(job__onetimejob__configuration=configuration)
            ).distinct()
        return qs


class JobChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj):
        return f"{obj.get_kind_display()}: {obj.definition}"


class BaseJobScopeForm(forms.ModelForm):
    job = JobChoiceField(queryset=Job.objects.all())
    tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    excluded_tags = forms.ModelMultipleChoiceField(queryset=Tag.objects.all(), required=False)
    serial_numbers = SimpleArrayField(forms.CharField(), required=False)
    excluded_serial_numbers = SimpleArrayField(forms.CharField(), required=False)

    def __init__(self, *args, configuration=None, **kwargs):
        super().__init__(*args, **kwargs)
        # NB: the UUID PK default fills pk at construction, so use _state.adding (not pk) for create-vs-update
        self.configuration = configuration or (None if self.instance._state.adding else self.instance.configuration)
        self.fields["job"].queryset = Job.objects.select_related("script", "mscp_check").all()

    def clean(self):
        cleaned_data = super().clean()
        tags = set(cleaned_data.get("tags") or [])
        excluded_tags = set(cleaned_data.get("excluded_tags") or [])
        if tags & excluded_tags:
            self.add_error("excluded_tags", "Tags and excluded tags must be disjoint")
        serial_numbers = set(cleaned_data.get("serial_numbers") or [])
        excluded_serial_numbers = set(cleaned_data.get("excluded_serial_numbers") or [])
        if serial_numbers & excluded_serial_numbers:
            self.add_error("excluded_serial_numbers", "Serial numbers and excluded serial numbers must be disjoint")
        return cleaned_data

    def save(self, *args, **kwargs):
        if self.configuration is not None:
            self.instance.configuration = self.configuration
        return super().save(*args, **kwargs)


class RecurringJobForm(BaseJobScopeForm):
    class Meta:
        model = RecurringJob
        fields = ("job", "interval", "tags", "excluded_tags", "serial_numbers", "excluded_serial_numbers")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.configuration is not None and self.instance._state.adding:
            # a job can be scheduled at most once per configuration (unique constraint)
            scheduled = RecurringJob.objects.filter(configuration=self.configuration).values_list("job_id", flat=True)
            self.fields["job"].queryset = self.fields["job"].queryset.exclude(pk__in=scheduled)


class RecurringJobSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label="Job or configuration name", required=False,
        widget=forms.TextInput(attrs={"autofocus": True, "size": 36}),
    )
    configuration = forms.ModelChoiceField(
        queryset=Configuration.objects.all(), required=False, empty_label="...",
    )
    kind = forms.ChoiceField(
        choices=[("", "...")] + list(Job.Kind.choices), required=False,
    )

    def get_queryset(self):
        qs = (
            RecurringJob.objects
            .select_related("configuration", "job__script", "job__mscp_check")
            .prefetch_related("tags", "excluded_tags")
            .annotate(job_name=Coalesce("job__script__name", "job__mscp_check__rule_id",
                                        output_field=TextField()))
            .order_by("job_name", "pk")
        )
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(
                Q(job__script__name__icontains=q)
                | Q(job__mscp_check__rule_id__icontains=q)
                | Q(configuration__name__icontains=q)
            )
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            qs = qs.filter(configuration=configuration)
        kind = self.cleaned_data.get("kind")
        if kind:
            qs = qs.filter(job__kind=kind)
        return qs


# datetime-local widget config shared by the one-time-job forms (not_before / not_after)
_DATETIME_LOCAL = {
    "required": False,
    "widget": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
    "input_formats": ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"],
}


class BaseOneTimeJobForm(forms.ModelForm):
    # the not_before / not_after window + its validation, shared by the scoped OneTimeJobForm and the
    # single-machine MachineOneTimeJobForm (no Meta here, like BaseJobScopeForm — subclasses set the model)
    not_before = forms.DateTimeField(**_DATETIME_LOCAL)
    not_after = forms.DateTimeField(**_DATETIME_LOCAL)

    def clean(self):
        cleaned_data = super().clean()
        not_before = cleaned_data.get("not_before")
        not_after = cleaned_data.get("not_after")
        if not_before and not_after and not_before > not_after:
            self.add_error("not_after", "not_after must be on or after not_before")
        return cleaned_data


class OneTimeJobForm(BaseJobScopeForm, BaseOneTimeJobForm):
    class Meta:
        model = OneTimeJob
        fields = ("job", "not_before", "not_after", "tags", "excluded_tags",
                  "serial_numbers", "excluded_serial_numbers")


class OneTimeJobSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label="Job or configuration name", required=False,
        widget=forms.TextInput(attrs={"autofocus": True, "size": 36}),
    )
    configuration = forms.ModelChoiceField(
        queryset=Configuration.objects.all(), required=False, empty_label="...",
    )
    kind = forms.ChoiceField(
        choices=[("", "...")] + list(Job.Kind.choices), required=False,
    )

    def get_queryset(self):
        qs = (
            OneTimeJob.objects
            .select_related("configuration", "job__script", "job__mscp_check")
            .prefetch_related("tags", "excluded_tags")
            .order_by(F("not_before").desc(nulls_last=True), "-created_at")
        )
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(
                Q(job__script__name__icontains=q)
                | Q(job__mscp_check__rule_id__icontains=q)
                | Q(configuration__name__icontains=q)
            )
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            qs = qs.filter(configuration=configuration)
        kind = self.cleaned_data.get("kind")
        if kind:
            qs = qs.filter(job__kind=kind)
        return qs


class EnrolledMachineSearchForm(forms.Form):
    template_name = "django/forms/search.html"

    q = forms.CharField(
        label="Serial number", required=False,
        widget=forms.TextInput(attrs={"autofocus": True, "size": 36}),
    )
    configuration = forms.ModelChoiceField(
        queryset=Configuration.objects.all(), required=False, empty_label="...",
    )

    def get_queryset(self):
        qs = EnrolledMachine.objects.latest_per_serial().order_by(
            F("last_seen_at").desc(nulls_last=True), "serial_number")
        q = self.cleaned_data.get("q")
        if q:
            qs = qs.filter(serial_number__icontains=q)
        configuration = self.cleaned_data.get("configuration")
        if configuration:
            qs = qs.filter(enrollment__configuration=configuration)
        return qs


class MachineOneTimeJobForm(BaseOneTimeJobForm):
    job = JobChoiceField(queryset=Job.objects.all())

    class Meta:
        model = OneTimeJob
        fields = ("job", "not_before", "not_after")

    def __init__(self, *args, configuration=None, serial_number=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.configuration = configuration
        self.serial_number = serial_number
        self.fields["job"].queryset = Job.objects.select_related("script", "mscp_check").all()

    def save(self, *args, **kwargs):
        # locked to one machine: the view supplies the config + serial, no scope UI
        self.instance.configuration = self.configuration
        self.instance.serial_numbers = [self.serial_number]
        return super().save(*args, **kwargs)
