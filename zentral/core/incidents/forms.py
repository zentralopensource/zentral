from django import forms
from django.db.models import Q
from .models import Incident, MachineIncident, Severity, Status
from .utils import update_incident_status, update_machine_incident_status


class IncidentSearchForm(forms.Form):
    q = forms.CharField(label="Query", required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Keywords…"}))
    severity = forms.ChoiceField(label="Severity", choices=[], required=False)
    status = forms.ChoiceField(label="Status", choices=[], required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        severity_choices_dict = dict(Severity.choices())
        self.fields["severity"].choices = [("", "----")]
        for severity in sorted(Incident.objects.values_list("severity", flat=True).distinct().order_by("severity")):
            self.fields["severity"].choices.append(
                (str(severity), severity_choices_dict.get(severity, str(severity)))
            )
        status_choices_dict = dict(Status.choices())
        self.fields["status"].choices = [("", "----")]
        for status in Incident.objects.values_list("status", flat=True).distinct().order_by("status"):
            self.fields["status"].choices.append(
                (status, status_choices_dict.get(status, status))
            )

    def clean_severity(self):
        severity = self.cleaned_data.get("severity")
        try:
            return int(severity)
        except (TypeError, ValueError):
            pass

    def get_queryset(self):
        cleaned_data = self.cleaned_data
        qs = Incident.objects.all()
        q = cleaned_data.get("q")
        if q:
            qs = qs.filter(Q(name__icontains=q)
                           | Q(description__icontains=q)
                           | Q(probe_source__name__icontains=q)
                           | Q(probe_source__description__icontains=q)
                           | Q(probe_source__body__icontains=q))
        severity = cleaned_data.get("severity")
        if severity:
            qs = qs.filter(severity=severity)
        status = cleaned_data.get("status")
        if status:
            qs = qs.filter(status=status)
        return qs

    def is_initial(self):
        return {k: v for k, v in self.cleaned_data.items() if v} == {}


class UpdateIncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ("status",)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super().__init__(*args, **kwargs)
        self.fields["status"].choices = self.instance.get_next_status_choices()

    def save(self, *args, **kwargs):
        incident, self.event = update_incident_status(self.instance,
                                                      Status(self.cleaned_data.get("status")),
                                                      self.request)
        return incident

    def post_event(self):
        if self.event:
            self.event.post()


class UpdateMachineIncidentForm(forms.ModelForm):
    class Meta:
        model = MachineIncident
        fields = ("status",)

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request")
        super().__init__(*args, **kwargs)
        self.fields["status"].choices = self.instance.get_next_status_choices()

    def save(self, *args, **kwargs):
        machine_incident, self.event = update_machine_incident_status(self.instance,
                                                                      Status(self.cleaned_data.get("status")),
                                                                      self.request)
        return machine_incident

    def post_event(self):
        if self.event:
            self.event.post()
