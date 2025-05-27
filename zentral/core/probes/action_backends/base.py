import logging
from zentral.utils.backend_model import Backend


logger = logging.getLogger('zentral.core.probes.action_backends.base')


class BaseAction(Backend):
    # to implement in the subclasses
    def trigger(self, event, probe):
        raise NotImplementedError
