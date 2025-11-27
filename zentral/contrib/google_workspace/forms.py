import json
from django import forms
from .models import Connection, GroupTagMapping
from .api_client import APIClient, InstalledAppFlow, validate_group_in_connection


class ConnectionForm(forms.ModelForm):
    serialized_client_config = forms.FileField(label="Client config")

    class Meta:
        model = Connection
        fields = ("name", "serialized_client_config")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reauthorization_required = False
        if self.instance.name:  # this checks if instance is a new object initialized without a name
            self.fields["serialized_client_config"].required = False

    def clean_serialized_client_config(self):
        f = self.cleaned_data["serialized_client_config"]
        if f:
            try:
                content = f.read().decode("utf-8")
                InstalledAppFlow.from_client_config(json.loads(content), APIClient.scopes)
            except Exception:
                raise forms.ValidationError("Invalid client config")
            else:
                self.instance.set_client_config(content)
                self.reauthorization_required = True


class GroupTagMappingForm(forms.ModelForm):

    class Meta:
        model = GroupTagMapping
        fields = ("group_email", "tags", )

    def __init__(self, *args, **kwargs):
        self.connection = kwargs.pop("connection")
        super().__init__(*args, **kwargs)

    def clean_group_email(self):
        group_email = self.cleaned_data["group_email"]
        if (GroupTagMapping.objects
                .filter(group_email=group_email, connection=self.connection)
                .exclude(pk=self.instance.pk)
                .exists()):
            raise forms.ValidationError("A mapping for this group already exists.")

        validate_group_in_connection(self.connection, group_email,
                                     lambda: forms.ValidationError("Group email not found for this connection."))

        return group_email

    def save(self, *args, **kwargs):
        self.instance.connection = self.connection
        return super().save(*args, **kwargs)
