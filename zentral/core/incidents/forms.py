from django import forms
from django.db.models import Q
from .events import build_incident_events
from .models import Incident, MachineIncident, SEVERITY_CHOICES, STATUS_CHOICES
from .utils import update_incident_status, update_machine_incident_status


class IncidentSearchForm(forms.Form):
    q = forms.CharField(label="Query", required=False,
                        widget=forms.TextInput(attrs={"placeholder": "Keywords…"}))
    severity = forms.ChoiceField(label="Severity", choices=[], required=False)
    status = forms.ChoiceField(label="Status", choices=[], required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        severity_choices_dict = dict(SEVERITY_CHOICES)
        self.fields["severity"].choices = [("", "----")]
        for severity in sorted(Incident.objects.values_list("severity", flat=True).distinct().order_by("severity")):
            self.fields["severity"].choices.append(
                (str(severity), severity_choices_dict.get(severity, str(severity)))
            )
        status_choices_dict = dict(STATUS_CHOICES)
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
        super().__init__(*args, **kwargs)
        self.fields["status"].choices = self.instance.get_next_status_choices()

    def save(self, *args, **kwargs):
        incident, incident_event_payloads = update_incident_status(self.instance,
                                                                   self.cleaned_data.get("status"))
        for event in build_incident_events(incident_event_payloads):
            event.post()
        return incident


class UpdateMachineIncidentForm(forms.ModelForm):
    class Meta:
        model = MachineIncident
        fields = ("status",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["status"].choices = self.instance.get_next_status_choices()

    def save(self, *args, **kwargs):
        machine_incident, incident_event_payloads = update_machine_incident_status(self.instance,
                                                                                   self.cleaned_data.get("status"))
        for event in build_incident_events(incident_event_payloads, machine_incident.serial_number):
            event.post()
        return machine_incident
