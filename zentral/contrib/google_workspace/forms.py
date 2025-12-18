import json
from django import forms
from .models import Connection, GroupTagMapping
from .api_client import _AdminSDKClient, APIClient, InstalledAppFlow, validate_group_in_connection


class ConnectionForm(forms.ModelForm):
    serialized_client_config = forms.FileField(label="Client config", required=False)

    class Meta:
        model = Connection
        fields = ("name", "type", "customer_id", "serialized_client_config")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reauthorization_required = False

    def clean(self):
        data = super().clean()
        match data["type"]:
            case Connection.Type.OAUTH_ADMIN_SDK:
                f = data.get("serialized_client_config")
                if f:
                    try:
                        content = f.read().decode("utf-8")
                        InstalledAppFlow.from_client_config(json.loads(content), _AdminSDKClient.scopes)
                    except Exception:
                        self.add_error("serialized_client_config", "Invalid client config.")
                    else:
                        self.instance.set_client_config(content)
                        self.reauthorization_required = True
                elif not self.instance.name:
                    self.add_error("serialized_client_config", 
                                   f"Required for {Connection.Type.OAUTH_ADMIN_SDK.label} connection.")

            case Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY:
                customer_id = data.get("customer_id")
                if not customer_id:
                    self.add_error("customer_id",
                                   f"Required for {Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY.label} connection.")
                elif not customer_id.startswith("C"):
                    self.add_error("customer_id", "Invalid customer id.")
                else:
                    api_client = APIClient.from_customer_id(data["name"], customer_id)
                    if not api_client.is_healthy():
                        self.add_error("customer_id", "Customer ID is not supported.")
        return data


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
