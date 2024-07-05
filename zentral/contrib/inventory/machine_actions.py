from django.urls import reverse
from .models import MetaMachine


class MachineAction:
    category = None
    title = None
    description = None
    display_class = ""
    url_name = None
    permission_required = None

    def __init__(self, serial_number, user):
        self.serial_number = serial_number
        self.user = user

    # machine

    def check_machine(self):
        return True

    # permissions

    def get_permission_required(self):
        if not self.permission_required:
            return
        if isinstance(self.permission_required, str):
            yield self.permission_required
        else:
            yield from self.permission_required

    def check_permissions(self):
        return self.user.has_perms(self.get_permission_required())

    # Link

    def get_url_kwargs(self):
        return {"urlsafe_serial_number": MetaMachine.make_urlsafe_serial_number(self.serial_number)}

    def get_url(self):
        return reverse(self.url_name, kwargs=self.get_url_kwargs())

    def get_disabled(self):
        return not self.check_machine() or not self.check_permissions()


class ManageTags(MachineAction):
    title = "Manage tags"
    description = "Manage the machine tags"
    url_name = "inventory:machine_tags"
    permission_required = (
        "inventory.view_machinetag",
        "inventory.add_machinetag",
        "inventory.change_machinetag",
        "inventory.delete_machinetag",
        "inventory.add_tag",
    )


class ArchiveMachine(MachineAction):
    title = "Archive machine"
    description = "Archive the machine. It will be hidden from the inventory."
    display_class = "danger"
    url_name = "inventory:archive_machine"
    permission_required = "inventory.change_machinesnapshot"


actions = [ManageTags, ArchiveMachine]
