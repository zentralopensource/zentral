from django import forms
from zentral.core.probes.forms import BaseCreateProbeForm
from zentral.utils.forms import validate_sha256
from .models import Configuration, Enrollment
from .probes import (OsqueryProbe, OsqueryComplianceProbe,
                     OsqueryDistributedQueryProbe, OsqueryFileCarveProbe,
                     OsqueryFIMProbe)
from .releases import get_osquery_versions


# Configuration / Enrollment

class ConfigurationForm(forms.ModelForm):
    class Meta:
        model = Configuration
        fields = '__all__'


class EnrollmentForm(forms.ModelForm):
    osquery_release = forms.ChoiceField(
        label="Osquery release",
        choices=[],
        initial="",
        help_text="Choose an osquery release to be installed by the enrollment package.",
        required=False
    )

    class Meta:
        model = Enrollment
        fields = ("configuration", "osquery_release")

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

        # release
        release_field = self.fields["osquery_release"]
        if self.update_for:
            release_field.widget = forms.HiddenInput()
        else:
            release_choices = [
                (version,
                 "{}{} ({})".format(
                     version,
                     " - prerelease -" if prerelease else "",
                     ", ".join(sorted(available_assets.keys()))
                 ))
                for version, prerelease, available_assets in get_osquery_versions()
            ]
            if not self.standalone:
                release_choices.insert(0, ("", "Do not include osquery"))
            release_field.choices = release_choices


# OsqueryProbe


class DiscoveryForm(forms.Form):
    query = forms.CharField(widget=forms.Textarea(attrs={'rows': 5}))

    def get_item_d(self):
        return self.cleaned_data["query"]

    @staticmethod
    def get_initial(discovery):
        return {"query": discovery}


class QueryForm(forms.Form):
    query = forms.CharField(widget=forms.Textarea(attrs={'rows': 5}))
    description = forms.CharField(required=False,
                                  help_text="Description of what this query does. Can be left empty",
                                  widget=forms.Textarea(attrs={'rows': 3}))
    value = forms.CharField(required=False,
                            help_text="Why is this query relevant. Can be left empty",
                            widget=forms.Textarea(attrs={'rows': 3}))
    removed = forms.BooleanField(label='Include {"action": "removed"} results?',
                                 help_text='If False, only {"action": "added"} results will be in the logs',
                                 initial=True,
                                 required=False)
    snapshot = forms.BooleanField(label='Run this query in "snapshot" mode?',
                                  help_text=('If True, osquery will not store differentials '
                                             'and will not emulate an event stream'),
                                  initial=False,
                                  required=False)
    interval = forms.IntegerField(min_value=10,  # 10 seconds
                                  max_value=2678400,  # 31 days
                                  initial=3600)
    shard = forms.IntegerField(min_value=1, max_value=100, required=False,
                               help_text="Restrict this query to a percentage (1-100) of target hosts")

    def clean_removed(self):
        remove = self.cleaned_data.get("removed")
        if not remove:
            remove = False
        return remove

    def clean_snapshot(self):
        snapshot = self.cleaned_data.get("snapshot")
        if not snapshot:
            snapshot = False
        return snapshot

    def clean_description(self):
        description = self.cleaned_data.get("description")
        if not description:
            return None
        else:
            return description

    def clean_value(self):
        value = self.cleaned_data.get("value")
        if not value:
            return None
        else:
            return value

    def clean(self):
        cleaned_data = super().clean()
        removed = cleaned_data["removed"]
        snapshot = cleaned_data["snapshot"]
        if removed and snapshot:
            raise forms.ValidationError('{"action": "removed"} results are not available in "snapshot" mode')
        return cleaned_data

    def get_item_d(self):
        return {f: v for f, v in self.cleaned_data.items() if v is not None}

    @staticmethod
    def get_initial(query):
        initial = {}
        for attr in ("query", "description", "value", "interval", "removed", "shard", "snapshot"):
            value = getattr(query, attr, None)
            if value is not None:
                initial[attr] = value
        return initial


class CreateProbeForm(BaseCreateProbeForm, QueryForm):
    model = OsqueryProbe
    field_order = ("name", "query", "description", "value", "removed", "snapshot", "interval", "shard")

    def get_body(self):
        return {"queries": [self.get_item_d()]}


# OsqueryComplianceProbe


class PreferenceFileForm(forms.Form):
    rel_path = forms.CharField(label="Relative path")
    type = forms.ChoiceField(label='Location',
                             choices=(('USERS', '/Users/%/Library/Preferences/'),
                                      ('GLOBAL', '/Library/Preferences/')))
    description = forms.CharField(required=False,
                                  widget=forms.Textarea(attrs={'rows': 3}))
    interval = forms.IntegerField(min_value=10,  # 10 seconds
                                  max_value=2678400,  # 31 days
                                  initial=3600)

    def clean_description(self):
        description = self.cleaned_data.get("description")
        if not description:
            return None
        else:
            return description

    def get_item_d(self):
        return {f: v for f, v in self.cleaned_data.items() if v is not None}

    @staticmethod
    def get_initial(query):
        initial = {}
        for attr in ("rel_path", "type", "description", "interval"):
            value = getattr(query, attr, None)
            if value is not None:
                initial[attr] = value
        return initial


class KeyForm(forms.Form):
    key = forms.CharField()
    test = forms.ChoiceField(choices=(('EQ', ' = '),
                                      ('INT_LTE', 'integer ≤'),
                                      ('INT_GTE', 'integer ≥'),
                                      ('INT_GTE_LTE', '≤ integer ≤')),
                             initial='STR',
                             widget=forms.Select(attrs={'class': 'key-test-sel'}))
    arg_l = forms.CharField(required=False)
    arg_r = forms.CharField(required=True)

    def clean(self):
        cd = self.cleaned_data
        test = cd.get('test')
        arg_l = cd.get('arg_l')
        arg_r = cd.get('arg_r')
        if test and test != 'EQ':
            if arg_r:
                try:
                    cd['arg_r'] = int(arg_r)
                except ValueError:
                    self.add_error('arg_r', 'not an integer')
            if test == 'INT_GTE_LTE':
                if arg_l is None:
                    self.add_error('arg_l', 'missing value')
                else:
                    try:
                        cd['arg_l'] = int(arg_l)
                    except ValueError:
                        self.add_error('arg_l', 'not an integer')
        return cd


class BaseKeyFormSet(forms.BaseFormSet):
    def clean(self):
        """Checks that no two keys are the same"""
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
        keys = []
        for form in self.forms:
            key = form.cleaned_data['key']
            if key in keys:
                raise forms.ValidationError("Articles in a set must have distinct titles.")
            keys.append(key)

    def get_keys(self):
        keys = []
        for kcd in self.cleaned_data:
            if not kcd.get("DELETE"):
                k = {'key': kcd['key']}
                test = kcd['test']
                arg_r = kcd['arg_r']
                if test == 'EQ':
                    k['value'] = arg_r
                elif test == 'INT_LTE':
                    k['max_value'] = arg_r
                elif test == 'INT_GTE':
                    k['min_value'] = arg_r
                else:
                    k['min_value'] = kcd['arg_l']
                    k['max_value'] = arg_r
                keys.append(k)
        return sorted(keys, key=lambda k: k['key'])

    @staticmethod
    def get_initial(preference_file):
        initial = []
        for k in preference_file.keys:
            key = {'key': k.key}
            if k.value is not None:
                key['arg_r'] = k.value
                key['test'] = 'EQ'
            else:
                min_value = k.min_value
                max_value = k.max_value
                if min_value is not None and max_value is not None:
                    key['test'] = 'INT_GTE_LTE'
                    key['arg_l'] = min_value
                    key['arg_r'] = max_value
                elif min_value is not None:
                    key['test'] = 'INT_GTE'
                    key['arg_r'] = min_value
                elif max_value is not None:
                    key['test'] = 'INT_LTE'
                    key['arg_r'] = max_value
            initial.append(key)
        return sorted(initial, key=lambda d: d['key'])


KeyFormSet = forms.formset_factory(KeyForm,
                                   formset=BaseKeyFormSet,
                                   min_num=1, max_num=10, extra=0, can_delete=True)


class FileChecksumForm(forms.Form):
    path = forms.CharField()
    sha256 = forms.CharField(validators=[validate_sha256],
                             help_text="The result of shasum -a 256 /path/to/file")
    description = forms.CharField(required=False,
                                  widget=forms.Textarea(attrs={'rows': 3}))
    interval = forms.IntegerField(min_value=10,  # 10 seconds
                                  max_value=2678400,  # 31 days
                                  initial=3600)

    def clean_description(self):
        description = self.cleaned_data.get("description")
        if not description:
            return None
        else:
            return description

    def get_item_d(self):
        return {f: v for f, v in self.cleaned_data.items() if v is not None}

    @staticmethod
    def get_initial(file_checksum):
        initial = {}
        for field in ("path", "sha256", "description", "interval"):
            val = getattr(file_checksum, field, None)
            if val:
                initial[field] = val
        return initial


class CreateComplianceProbeForm(BaseCreateProbeForm):
    model = OsqueryComplianceProbe

    def get_body(self):
        return {}


# OsqueryDistributedQueryProbe


class DistributedQueryForm(forms.Form):
    query = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control',
                                                         'rows': 5}))

    def get_body(self):
        return {'distributed_query': self.cleaned_data['query']}


class CreateDistributedQueryProbeForm(BaseCreateProbeForm, DistributedQueryForm):
    model = OsqueryDistributedQueryProbe
    field_order = ("name", "query")


class DistributedQueryResultFilterForm(forms.Form):
    ERROR = "error"
    EMPTY = "empty"
    NON_EMPTY = "non_empty"
    ALL = "all"
    STATUS_CHOICES = (
        (ERROR, "Error"),
        (EMPTY, "Empty"),
        (NON_EMPTY, "Non-Empty"),
        (ALL, "All")
    )
    status = forms.ChoiceField(choices=STATUS_CHOICES, initial=ALL)

    def get_filter_dict(self):
        cleaned_data = self.cleaned_data
        status = cleaned_data.get("status")
        if status == self.ERROR:
            return {"error": True, "empty": True}
        elif status == self.EMPTY:
            return {"error": False, "empty": True}
        elif status == self.NON_EMPTY:
            return {"error": False, "empty": False}
        else:
            return {}


# OsqueryFileCarveProbe


class FileCarveForm(forms.Form):
    path = forms.CharField(help_text="Example: /Users/%/Downloads/%.jpg or /etc/hosts")

    def get_body(self):
        return {'path': self.cleaned_data['path']}


class CreateFileCarveProbeForm(BaseCreateProbeForm, FileCarveForm):
    model = OsqueryFileCarveProbe
    field_order = ("name", "path")


# FIM probes


class FilePathForm(forms.Form):
    file_path = forms.CharField(help_text="Example: /Users/%/Library or /Users/%/Library/ or /Users/%/Library/%%")
    file_access = forms.BooleanField(label="Observe file access events ?", initial=False, required=False,
                                     help_text="File accesses on Linux using inotify may induce "
                                               "unexpected and unwanted performance reduction.")

    def clean_file_access(self):
        file_access = self.cleaned_data.get("file_access")
        if not file_access:
            file_access = False
        return file_access

    def get_item_d(self):
        return self.cleaned_data

    @staticmethod
    def get_initial(file_path):
        return {"file_path": file_path.file_path,
                "file_access": file_path.file_access}


class CreateFIMProbeForm(BaseCreateProbeForm, FilePathForm):
    model = OsqueryFIMProbe
    field_order = ("name", "file_path", "file_access")

    def get_body(self):
        return {'file_paths': [self.get_item_d()]}
