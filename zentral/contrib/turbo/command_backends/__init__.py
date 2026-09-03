from django.db import models


class CommandBackend(models.TextChoices):
    # lowercase, unlike the other BackendInstance enums: these values double as the wire `kind`, and
    # Turbo's wire convention wins over the UPPER_SNAKE enum convention of stores / probes.
    SYSDIAGNOSE = "sysdiagnose", "sysdiagnose"
    FILE_EXPORT = "file_export", "File export"


def get_command_backend_class(backend):
    # the imports are inside the branches, like probes.action_backends: the backend modules import
    # models.py (for ScheduleMode) and models.py imports this module (for CommandBackend.choices), so
    # only a lazy import keeps the loop open.
    #
    # The value is compared as-is rather than coerced through CommandBackend() first — a TextChoices
    # member IS its string, so the comparisons work either way, and this makes the final raise the one
    # gate. Coercing first would make it unreachable, and a value added to the enum but not mapped here
    # would then return None instead of failing.
    if backend == CommandBackend.SYSDIAGNOSE:
        from .sysdiagnose import Sysdiagnose
        return Sysdiagnose
    if backend == CommandBackend.FILE_EXPORT:
        from .file_export import FileExport
        return FileExport
    raise ValueError(f"Unknown command backend: {backend}")


def get_command_backend(command, load=False):
    return get_command_backend_class(command.backend)(command, load)
