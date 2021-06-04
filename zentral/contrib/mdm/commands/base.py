import logging
import plistlib
import uuid
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.models import Channel, CommandStatus, DeviceCommand, Platform, UserCommand


logger = logging.getLogger("zentral.contrib.mdm.commands.base")


class Command:
    request_type = None
    allowed_channel = None
    allowed_platform = None
    allowed_in_user_enrollment = False
    artifact_operation = None

    @classmethod
    def _verify_channel(cls, channel):
        allowed_channels = cls.allowed_channel
        if isinstance(allowed_channels, Channel):
            allowed_channels = (allowed_channels,)
        if channel not in allowed_channels:
            raise ValueError("Incompatible channel")

    @classmethod
    def _verify_platforms(cls, enrolled_device):
        allowed_platforms = cls.allowed_platform
        if isinstance(allowed_platforms, Platform):
            allowed_platforms = (allowed_platforms,)
        if any(enrolled_device.platform == p.name for p in allowed_platforms):
            return
        raise ValueError("Incompatible platform")

    @classmethod
    def create_for_device(cls, enrolled_device, artifact_version=None, kwargs=None, queue=False):
        cls._verify_channel(Channel.Device)
        cls._verify_platforms(enrolled_device)
        return cls(Channel.Device, DeviceCommand(enrolled_device=enrolled_device,
                                                 artifact_version=artifact_version,
                                                 kwargs=kwargs or {},
                                                 time=None if queue else timezone.now()))

    @classmethod
    def create_for_user(cls, enrolled_user, artifact_version=None, kwargs=None, queue=False):
        cls._verify_channel(Channel.User)
        cls._verify_platforms(enrolled_user.enrolled_device)
        return cls(Channel.User, UserCommand(enrolled_user=enrolled_user,
                                             artifact_version=artifact_version,
                                             kwargs=kwargs or {},
                                             time=None if queue else timezone.now()))

    def load_kwargs(self):
        pass

    def __init__(self, channel, db_command):
        self.channel = channel
        self.db_command = db_command
        if self.db_command.pk:
            # command loaded from db
            self.load_kwargs()
        else:
            # new command
            self.db_command.uuid = uuid.uuid4()
            self.db_command.name = self.request_type
            if self.artifact_operation:
                self.db_command.artifact_operation = self.artifact_operation.name
            self.db_command.save()
        # enrolled objects
        self.enrolled_device = getattr(db_command, "enrolled_device", None)
        self.enrolled_user = getattr(db_command, "enrolled_user", None)
        if self.enrolled_user:
            self.enrolled_device = self.enrolled_user.enrolled_device
        # artifact?
        self.artifact_version = None
        self.artifact = None
        if self.db_command.artifact_version:
            self.artifact_version = self.db_command.artifact_version
            self.artifact = self.artifact_version.artifact

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.db_command.uuid == other.db_command.uuid
        return False

    def build_command(self):
        return {}

    def build_http_response(self, enrollment_session):
        self.enrollment_session = enrollment_session
        self.realm_user = self.enrollment_session.realm_user
        command = self.build_command()
        command["RequestType"] = self.request_type
        body = plistlib.dumps({"CommandUUID": str(self.db_command.uuid).upper(),
                               "Command": command})
        return HttpResponse(body, content_type="application/xml; charset=UTF-8")

    def process_response(self, response, enrollment_session, meta_business_unit):
        if self.db_command.result_time:
            logger.error("Command {self.db_command.uuid} has already been processed")
            return
        self.db_command.result_time = timezone.now()
        self.db_command.status = response["Status"]
        self.db_command.error_chain = response.get("ErrorChain")
        self.db_command.save()
        self.response = response
        self.enrollment_session = enrollment_session
        self.realm_user = enrollment_session.realm_user
        self.meta_business_unit = meta_business_unit
        if self.db_command.status == CommandStatus.Acknowledged.value:
            self.command_acknowledged()

    def command_acknowledged(self):
        pass

    def set_time(self):
        if self.db_command.time:
            raise ValueError("Command {self.db_command.uuid} has time")
        self.db_command.time = timezone.now()
        self.db_command.save()


registered_commands = {}


def register_command(command_cls):
    registered_commands[command_cls.request_type] = command_cls
