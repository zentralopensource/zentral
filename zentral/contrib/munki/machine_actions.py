from zentral.contrib.inventory.machine_actions import MachineAction
from .models import MunkiState


class ForceFullSync(MachineAction):
    category = "Munki"
    title = "Force full sync"
    description = "Force the script checks to run and all the managed install reports to be uploaded."
    url_name = "munki:force_machine_full_sync"
    permission_required = "munki.change_munkistate"

    def __init__(self, serial_number, user):
        super().__init__(serial_number, user)
        self.munki_state = MunkiState.objects.filter(machine_serial_number=serial_number).first()

    def check_machine(self):
        return self.munki_state is not None


actions = [ForceFullSync]
