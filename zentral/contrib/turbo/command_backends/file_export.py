import logging

from rest_framework import serializers

from ..models import ScheduleMode
from . import CommandBackend
from .base import Artifact, BaseCommand


logger = logging.getLogger("zentral.contrib.turbo.command_backends.file_export")


# fnmatch has no recursive wildcard, so a tree needs one pattern for each level. See
# validate_pattern. A support workflow with a few directories uses many patterns.
MAX_PATTERNS = 32
MAX_PATTERN_LENGTH = 1024
DEFAULT_MAX_SIZE = 100 * 2**20
MAX_MAX_SIZE = 500 * 2**20
# The limit applies to the uncompressed total, so the compressed limit is the same value.
# Zentral refuses a mint above it in both cases.
MAX_UPLOAD_SIZE = MAX_MAX_SIZE


def validate_pattern(value):
    if not value.startswith("/"):
        raise serializers.ValidationError("Must be an absolute path")
    # A .. segment leaves the directory that the pattern names. Reject the segment. Do not
    # normalize it, so that the agent walks what the operator reads.
    if ".." in value.split("/"):
        raise serializers.ValidationError("Must not contain a .. segment")
    # The agent matches with fnmatch(3), which macOS supplies. fnmatch has no recursive
    # wildcard, and it accepts **: two stars are two stars. With FNM_PATHNAME,
    # `/Library/Logs/**/*.log` matches `/Library/Logs/a/b.log` but not
    # `/Library/Logs/a/b/c.log`. A pattern for a recursive walk collects one level only, with no
    # error. Refuse the pattern here, or the operator finds this out from a short archive.
    if "**" in value:
        raise serializers.ValidationError(
            "Must not contain **: the patterns are matched with fnmatch, which has no recursive "
            "wildcard. Add one pattern for each directory level."
        )
    return value


class FileExportKwargsSerializer(serializers.Serializer):
    # A list, because a support workflow collects several paths in one run, one archive and one
    # limit. One pattern is a list of one. The syntax is fnmatch: `*`, `?` and `[...]`. A `*`
    # stops at a `/` (FNM_PATHNAME), so a pattern names one directory level.
    patterns = serializers.ListField(
        child=serializers.CharField(max_length=MAX_PATTERN_LENGTH, validators=[validate_pattern]),
        min_length=1,
        max_length=MAX_PATTERNS,
    )
    # The UNCOMPRESSED total. stat gives the size of a file, so the agent decides on a file
    # before it writes anything.
    max_size = serializers.IntegerField(min_value=1, max_value=MAX_MAX_SIZE, default=DEFAULT_MAX_SIZE)


class FileExport(BaseCommand):
    kind = CommandBackend.FILE_EXPORT
    kwargs_keys = ("patterns", "max_size")
    kwargs_serializer = FileExportKwargsSerializer
    allowed_modes = frozenset([ScheduleMode.ONE_TIME])
    requires_upload = True
    artifacts = (
        # A separate artifact, not a file in the archive. An operator reads a few KB without a
        # download of the whole archive. The list of the collected files also remains available
        # if the archive upload fails.
        Artifact(name="manifest", stem="file_export_manifest", extension=".json",
                 content_type="application/json"),
        # Optional. A run with no match has nothing to archive, and an empty archive gives the
        # operator no information.
        Artifact(name="archive", stem="file_export", extension=".zip",
                 content_type="application/zip", optional=True),
    )
    max_upload_size = MAX_UPLOAD_SIZE

    def wire_payload(self):
        return {"patterns": self.patterns, "max_size": self.max_size}
