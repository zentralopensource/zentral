import logging

from rest_framework import serializers

from ..models import ScheduleMode
from . import CommandBackend
from .base import Artifact, BaseCommand


logger = logging.getLogger("zentral.contrib.turbo.command_backends.sysdiagnose")


# 2 GiB. A sysdiagnose archive on a loaded system is more than 1 GB. The limit is a server
# constant, not a kwarg, because an operator has no reason to change it.
MAX_UPLOAD_SIZE = 2 * 2**30


class SysdiagnoseKwargsSerializer(serializers.Serializer):
    # No options. The agent controls the timeout and the invocation. This is why an operator can
    # start one from a machine page with one click.
    pass


class Sysdiagnose(BaseCommand):
    kind = CommandBackend.SYSDIAGNOSE
    kwargs_keys = ()
    kwargs_serializer = SysdiagnoseKwargsSerializer
    allowed_modes = frozenset([ScheduleMode.ONE_TIME])
    requires_upload = True
    artifacts = (
        # The tool writes its own compressed archive, and the agent does not compress it again.
        # The extension is the tool's.
        Artifact(name="archive", stem="sysdiagnose", extension=".tar.gz", content_type="application/gzip"),
    )
    max_upload_size = MAX_UPLOAD_SIZE

    def wire_payload(self):
        return {}
