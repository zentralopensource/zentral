import logging

from rest_framework import serializers

from ..models import ScheduleMode
from . import CommandBackend
from .base import Artifact, BaseCommand


logger = logging.getLogger("zentral.contrib.turbo.command_backends.file_export")


# fnmatch has no recursive wildcard, so a tree costs one pattern per level (see validate_pattern):
# a support workflow bundling a handful of directories spends patterns quickly
MAX_PATTERNS = 32
MAX_PATTERN_LENGTH = 1024
DEFAULT_MAX_SIZE = 100 * 2**20
MAX_MAX_SIZE = 500 * 2**20
# the archive can hold nothing but the cap is on the uncompressed total, so the compressed ceiling is
# the same as the uncompressed one — a mint is refused above it either way
MAX_UPLOAD_SIZE = MAX_MAX_SIZE


def validate_pattern(value):
    if not value.startswith("/"):
        raise serializers.ValidationError("Must be an absolute path")
    # a .. segment escapes the directory the pattern appears to name; reject the segment rather than
    # normalizing, so what an operator reads is what the agent walks
    if ".." in value.split("/"):
        raise serializers.ValidationError("Must not contain a .. segment")
    # The agent matches with fnmatch(3), which is what macOS gives it for free — and fnmatch has no
    # recursive wildcard. It does not reject **: two stars are simply two stars, so with FNM_PATHNAME
    # `/Library/Logs/**/*.log` matches `/Library/Logs/a/b.log` and NOT `/Library/Logs/a/b/c.log`. A
    # pattern written for recursion would therefore collect exactly one level, quietly. Refuse it here
    # rather than let an operator discover it from a short archive.
    if "**" in value:
        raise serializers.ValidationError(
            "Must not contain **: the patterns are matched with fnmatch, which has no recursive "
            "wildcard. Add one pattern for each directory level."
        )
    return value


class FileExportKwargsSerializer(serializers.Serializer):
    # a list because support workflows bundle several paths into one run, one archive and one gate;
    # a single pattern is just a list of one. fnmatch syntax — `*`, `?` and `[...]`, with `*` stopping
    # at a `/` (FNM_PATHNAME), so a pattern names one directory level and depth is spelled out.
    patterns = serializers.ListField(
        child=serializers.CharField(max_length=MAX_PATTERN_LENGTH, validators=[validate_pattern]),
        min_length=1,
        max_length=MAX_PATTERNS,
    )
    # UNCOMPRESSED total, unlike os_log's compressed cap: file sizes are known from stat, so inclusion
    # is decided before anything is written
    max_size = serializers.IntegerField(min_value=1, max_value=MAX_MAX_SIZE, default=DEFAULT_MAX_SIZE)


class FileExport(BaseCommand):
    kind = CommandBackend.FILE_EXPORT
    kwargs_keys = ("patterns", "max_size")
    kwargs_serializer = FileExportKwargsSerializer
    allowed_modes = frozenset([ScheduleMode.ONE_TIME])
    requires_upload = True
    artifacts = (
        # the manifest used to live inside the archive, to keep one upload per run. It comes out because
        # pulling the whole archive to read a few KB is the wrong shape for a support workflow, and
        # because a separate artifact means the inventory of what was collected survives an archive that
        # never uploaded.
        Artifact(name="manifest", stem="file_export_manifest", extension=".json",
                 content_type="application/json"),
        # optional: a zero-match run has nothing to archive, and an empty archive would be a fiction
        # someone has to open to disbelieve
        Artifact(name="archive", stem="file_export", extension=".zip",
                 content_type="application/zip", optional=True),
    )
    max_upload_size = MAX_UPLOAD_SIZE

    def wire_payload(self):
        return {"patterns": self.patterns, "max_size": self.max_size}
