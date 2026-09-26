import logging
from typing import NamedTuple

from zentral.utils.backend_model import Backend


logger = logging.getLogger("zentral.contrib.turbo.command_backends.base")


class Artifact(NamedTuple):
    """One output a command run produces.

    The declaration is the server's, never the agent's: it validates the `artifact` a mint asks for,
    builds the object's filename, and makes a result checkable against the set that was expected.
    `optional` means *this run may not have produced it* — a zero-match file_export has no archive to
    send — and it is the only legitimate reason an entry is missing from a completed run's result. An
    artifact that was produced and failed to upload is a different thing: it is reported, with its error.
    """
    name: str            # the wire `artifact`
    stem: str            # filename stem, before the serial and the mint timestamp
    extension: str
    content_type: str
    optional: bool = False


class BaseCommand(Backend):
    # the wire `kind`, equal to the CommandBackend value and to Job.kind
    kind = None
    # DRF serializer for backend_kwargs. The API and a future TF schema both use it. A kind with
    # no options declares a serializer with no fields, not None, to avoid a special case.
    kwargs_serializer = None
    # Every backend declares a set of ScheduleMode values and the artifacts of a run. An empty
    # default means "no schedule mode" and "no artifact", so test_command_backends asserts that
    # a backend replaces both.
    allowed_modes = frozenset()
    artifacts = ()
    requires_upload = False

    def wire_payload(self):
        raise NotImplementedError

    @classmethod
    def get_artifact(cls, name):
        for artifact in cls.artifacts:
            if artifact.name == name:
                return artifact
