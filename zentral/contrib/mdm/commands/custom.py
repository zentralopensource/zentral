import logging
import plistlib
from django import forms
from django.core.exceptions import ValidationError
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.custom")


class CustomCommand(Command):
    db_name = "CustomCommand"
    store_result = True
    reschedule_notnow = True

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return True

    def load_kwargs(self):
        self.command = plistlib.loads(self.db_command.kwargs["command"].encode("utf-8"))
        self.request_type = self.command.pop("RequestType")

    def build_command(self):
        return self.command


register_command(CustomCommand)


class CustomCommandForm(forms.Form):
    command = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 10}),
        help_text="The property list representation of the command (RequestType and optional keyword arguments)."
    )

    def clean_command(self):
        cmd = self.cleaned_data.get("command")
        if cmd:
            if cmd.startswith("<dict>"):
                # to make it easier for the users
                cmd = f'<plist version="1.0">{cmd}</plist>'
            try:
                loaded_cmd = plistlib.loads(cmd.encode("utf-8"))
            except Exception:
                raise ValidationError("Invalid property list")
            if not isinstance(loaded_cmd, dict):
                raise ValidationError("Not a dictionary")
            request_type = loaded_cmd.get("RequestType")
            if not request_type:
                raise ValidationError("Missing or empty RequestType")
            cmd = plistlib.dumps(loaded_cmd).decode("utf-8")
        return cmd
