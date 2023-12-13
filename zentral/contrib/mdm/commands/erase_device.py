import logging
from django import forms
from zentral.contrib.mdm.models import Channel, Platform
from zentral.core.secret_engines import decrypt_str, encrypt_str
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.erase_device")


class EraseDeviceForm(CommandBaseForm):
    disallow_proximity_setup = forms.BooleanField(
        label="Disallow proximity setup", initial=True,
        help_text="If true, disable Proximity Setup on the next reboot and skip the pane in Setup Assistant."
    )
    preserve_data_plan = forms.BooleanField(
        label="Preserve data plan", initial=True,
        help_text="If true, preserve the data plan on an iPhone or iPad with eSIM functionality, if one exists."
    )
    pin = forms.RegexField(label="PIN", min_length=6, max_length=6, strip=True, regex=r"[a-zA-Z0-9]{6}",
                           help_text="The six-character PIN for Find My.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_mobile_device = self.enrolled_device.platform in (Platform.IOS, Platform.IPADOS)
        self.pin_required = (
            # Intel Macs with a T1 or no security chip need a PIN
            self.enrolled_device.platform == Platform.MACOS
            and not self.enrolled_device.apple_silicon  # Not Apple Silicon
            and not self.enrolled_device.activation_lock_manageable  # Not a T2
        )
        if not self.is_mobile_device:
            self.fields.pop("disallow_proximity_setup")
            self.fields.pop("preserve_data_plan")
        if not self.pin_required:
            self.fields.pop("pin")

    def get_command_kwargs(self, uuid):
        kwargs = {}
        if self.is_mobile_device:
            kwargs["DisallowProximitySetup"] = self.cleaned_data.get("disallow_proximity_setup", False)
            kwargs["PreserveDataPlan"] = self.cleaned_data.get("preserve_data_plan", False)
        if self.pin_required:
            kwargs["PIN"] = encrypt_str(
                self.cleaned_data.get("pin"),
                model="mdm.devicecommand", field="PIN", uuid=str(uuid)
            )
        return kwargs


class EraseDevice(Command):
    request_type = "EraseDevice"
    display_name = "Erase Device"
    reschedule_notnow = True
    form_class = EraseDeviceForm

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return channel == Channel.DEVICE

    def load_pin(self):
        encrypted_pin = self.db_command.kwargs.get("PIN")
        if encrypted_pin:
            return decrypt_str(encrypted_pin, model="mdm.devicecommand", field="PIN", uuid=str(self.uuid))

    def build_command(self):
        payload = {}
        for attr in ("DisallowProximitySetup", "PreserveDataPlan"):
            val = self.db_command.kwargs.get(attr)
            if val is not None:
                payload[attr] = val
        pin = self.load_pin()
        if pin:
            payload["PIN"] = pin
        return payload


register_command(EraseDevice)
