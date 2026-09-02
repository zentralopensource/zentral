import logging

from rest_framework import serializers

from ..models import ScheduleMode
from . import CommandBackend
from .base import Artifact, BaseCommand


logger = logging.getLogger("zentral.contrib.turbo.command_backends.sysdiagnose")


# 2 GiB: sysdiagnose archives on a loaded system pass 1 GB, and the ceiling is a server constant
# rather than a kwarg because there is nothing an operator could usefully tune here
MAX_UPLOAD_SIZE = 2 * 2**30


class SysdiagnoseKwargsSerializer(serializers.Serializer):
    # no options: the agent owns the timeout and the invocation. Zero config is what makes the
    # machine-page one-click flow possible.
    pass


class Sysdiagnose(BaseCommand):
    kind = CommandBackend.SYSDIAGNOSE
    kwargs_keys = ()
    kwargs_serializer = SysdiagnoseKwargsSerializer
    allowed_modes = frozenset([ScheduleMode.ONE_TIME])
    requires_upload = True
    artifacts = (
        # the tool emits its own compressed archive and the agent does not recompress it, so the
        # extension is the tool's, not ours
        Artifact(name="archive", stem="sysdiagnose", extension=".tar.gz", content_type="application/gzip"),
    )
    max_upload_size = MAX_UPLOAD_SIZE

    def wire_payload(self):
        return {}
