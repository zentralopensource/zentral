from django.db import models


class CommandBackend(models.TextChoices):
    # Lowercase, unlike the other BackendInstance enums. These values are also the wire `kind`,
    # and the wire convention has priority over the UPPER_SNAKE convention of stores and probes.
    SYSDIAGNOSE = "sysdiagnose", "sysdiagnose"
    FILE_EXPORT = "file_export", "File export"


def get_command_backend_class(backend):
    # The imports are in the branches, like probes.action_backends. A backend module imports
    # models.py for ScheduleMode, and models.py imports this module for CommandBackend.choices.
    # A lazy import breaks that loop.
    #
    # The comparisons use the value as it is. They do not coerce it with CommandBackend() first,
    # because a TextChoices member is its string. The final raise is then the only gate: with a
    # coercion first, a value in the enum but not in the branches returns None instead.
    if backend == CommandBackend.SYSDIAGNOSE:
        from .sysdiagnose import Sysdiagnose
        return Sysdiagnose
    if backend == CommandBackend.FILE_EXPORT:
        from .file_export import FileExport
        return FileExport
    raise ValueError(f"Unknown command backend: {backend}")


def get_command_backend(command, load=False):
    return get_command_backend_class(command.backend)(command, load)
