import logging
from django import forms
from rest_framework import serializers
from zentral.contrib.mdm.models import Channel, Platform
from zentral.core.secret_engines import decrypt_str, encrypt_str
from .base import register_command, Command, CommandBaseForm, CommandBaseSerializer


logger = logging.getLogger("zentral.contrib.mdm.commands.device_lock")


class DeviceLockHelperMixin:
    pin_regex = r"[0-9]{6}"

    def update_fields(self):
        if not self.enrolled_device.platform == Platform.MACOS:
            self.fields.pop("pin")

    def get_command_kwargs_with_data(self, uuid, data):
        kwargs = {}
        message = data.get("message")
        if message:
            kwargs["Message"] = message
        phone_number = data.get("phone_number")
        if phone_number:
            kwargs["PhoneNumber"] = phone_number
        pin = data.get("pin")
        if pin:
            kwargs["PIN"] = encrypt_str(pin, model="mdm.devicecommand", field="PIN", uuid=str(uuid))
        return kwargs


class DeviceLockForm(DeviceLockHelperMixin, CommandBaseForm):
    message = forms.CharField(label="Message", max_length=255, required=False,
                              help_text="The message to display on the Lock screen of the device.")
    phone_number = forms.CharField(label="Phone number", max_length=15, required=False,
                                   help_text="The phone number to display on the Lock screen of the device.")
    pin = forms.RegexField(label="PIN", min_length=6, max_length=6,
                           strip=True, regex=DeviceLockHelperMixin.pin_regex,
                           help_text="6 numeric digits PIN.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.update_fields()

    def get_command_kwargs(self, uuid):
        return self.get_command_kwargs_with_data(uuid, self.cleaned_data)


class DeviceLockSerializer(DeviceLockHelperMixin, CommandBaseSerializer):
    message = serializers.CharField(max_length=255, required=False)
    phone_number = serializers.CharField(max_length=15, required=False)
    pin = serializers.RegexField(DeviceLockHelperMixin.pin_regex)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.update_fields()

    def get_command_kwargs(self, uuid):
        return self.get_command_kwargs_with_data(uuid, self.validated_data)


class DeviceLock(Command):
    request_type = "DeviceLock"
    display_name = "Device lock"
    reschedule_notnow = True
    form_class = DeviceLockForm
    serializer_class = DeviceLockSerializer

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and (not enrolled_device.user_enrollment or enrolled_device.platform in (Platform.IOS, Platform.IPADOS))
        )

    def load_pin(self):
        encrypted_pin = self.db_command.kwargs.get("PIN")
        if encrypted_pin:
            return decrypt_str(encrypted_pin, model="mdm.devicecommand", field="PIN", uuid=str(self.uuid))

    def build_command(self):
        payload = {}
        for attr in ("Message", "PhoneNumber"):
            val = self.db_command.kwargs.get(attr)
            if val:
                payload[attr] = val
        pin = self.load_pin()
        if pin:
            payload["PIN"] = pin
        return payload


register_command(DeviceLock)
