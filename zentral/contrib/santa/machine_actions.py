from pbac.engine import engine
from zentral.contrib.inventory.machine_actions import MachineAction
from zentral.contrib.inventory.models import MetaMachine
from .models import EnrolledMachine
from .pbac import ForceCleanSyncRequest


class BaseCleanSyncAction(MachineAction):
    category = "Santa"
    sync_type = None

    def __init__(self, serial_number, user):
        super().__init__(serial_number, user)
        enrolled_machines = EnrolledMachine.objects.get_for_serial_number(serial_number)
        self.enrolled_machine = enrolled_machines[0] if enrolled_machines else None

    def get_sync_type(self):
        return self.sync_type

    def check_permissions(self):
        # the action has no legacy permission to fall back on, and the PBAC request needs the
        # machine to carry its meta business units
        if self.enrolled_machine is None:
            return False
        pbac_request = ForceCleanSyncRequest(
            self.user, MetaMachine(self.serial_number), self.enrolled_machine, self.get_sync_type()
        )
        engine.authorize_request(pbac_request)
        return pbac_request.is_authorized


class BaseForceCleanSyncAction(BaseCleanSyncAction):
    url_name = "santa:force_machine_clean_sync"

    def check_machine(self):
        # a clean sync is already queued, the cancel action is the one that applies
        return self.enrolled_machine is not None and self.enrolled_machine.forced_sync_type is None

    def get_url_kwargs(self):
        kwargs = super().get_url_kwargs()
        kwargs["sync_type"] = self.sync_type
        return kwargs


class ForceCleanSync(BaseForceCleanSyncAction):
    title = "Force clean sync"
    description = "Rebuild the Santa rule database of the machine during its next preflight."
    sync_type = EnrolledMachine.SyncType.CLEAN


class ForceCleanAllSync(BaseForceCleanSyncAction):
    title = "Force clean all sync"
    description = ("Rebuild the Santa rule database of the machine during its next preflight,"
                   " transitive rules included.")
    display_class = "danger"
    sync_type = EnrolledMachine.SyncType.CLEAN_ALL


class CancelCleanSync(BaseCleanSyncAction):
    title = "Cancel queued clean sync"
    description = "Take back the clean sync queued for the machine."
    url_name = "santa:cancel_machine_clean_sync"

    def get_sync_type(self):
        # a cancellation is authorized against the sync type it takes back, so a role that may
        # only queue a CLEAN cannot cancel a queued CLEAN_ALL. Only reached with an enrolled
        # machine: check_permissions returns before it otherwise
        return self.enrolled_machine.forced_sync_type or EnrolledMachine.SyncType.CLEAN

    def check_machine(self):
        return self.enrolled_machine is not None and self.enrolled_machine.forced_sync_type is not None


actions = [ForceCleanSync, ForceCleanAllSync, CancelCleanSync]
