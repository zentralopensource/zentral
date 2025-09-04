import logging
import plistlib
from django import forms
from django.core.exceptions import ValidationError
from rest_framework import serializers
from .base import register_command, Command, CommandBaseForm, CommandBaseSerializer


logger = logging.getLogger("zentral.contrib.mdm.commands.custom")


def clean_command(cmd):
    if not cmd:
        raise ValueError("Empty command")
    if cmd.startswith("<dict>"):
        # to make it easier for the users
        cmd = f'<plist version="1.0">{cmd}</plist>'
    try:
        loaded_cmd = plistlib.loads(cmd.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid property list")
    if not isinstance(loaded_cmd, dict):
        raise ValueError("Not a dictionary")
    request_type = loaded_cmd.get("RequestType")
    if not request_type:
        raise ValueError("Missing or empty RequestType")
    return plistlib.dumps(loaded_cmd).decode("utf-8")


class CustomCommandForm(CommandBaseForm):
    command = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 10}),
        help_text="The property list representation of the command (RequestType and optional keyword arguments)."
    )

    def clean_command(self):
        try:
            return clean_command(self.cleaned_data.get("command"))
        except ValueError as e:
            raise ValidationError(str(e))

    def get_command_kwargs(self, uuid):
        return {"command": self.cleaned_data["command"]}


class CustomCommandSerializer(CommandBaseSerializer):
    command = serializers.CharField(required=True)

    def validate_command(self, value):
        try:
            return clean_command(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))

    def get_command_kwargs(self, uuid):
        return self.validated_data


class CustomCommand(Command):
    db_name = "CustomCommand"
    display_name = "Custom"
    store_result = True
    reschedule_notnow = True
    form_class = CustomCommandForm
    serializer_class = CustomCommandSerializer

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return True

    def load_kwargs(self):
        self.command = plistlib.loads(self.db_command.kwargs["command"].encode("utf-8"))
        self.request_type = self.command.pop("RequestType")

    def build_command(self):
        return self.command


register_command(CustomCommand)
