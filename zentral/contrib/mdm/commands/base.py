from datetime import timedelta
import logging
import plistlib
import uuid
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.models import Channel, CommandStatus, DeviceCommand, UserCommand


logger = logging.getLogger("zentral.contrib.mdm.commands.base")


class Command:
    request_type = None
    db_name = None
    artifact_operation = None
    store_result = False
    reschedule_notnow = False

    @classmethod
    def get_db_name(cls):
        return cls.db_name or cls.request_type

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        raise NotImplementedError

    @classmethod
    def create_for_target(
        cls,
        enrolled_device, target,
        artifact_version=None,
        kwargs=None,
        queue=False, delay=0
    ):
        if enrolled_device == target:
            channel = Channel.Device
            db_command = DeviceCommand(enrolled_device=target)
        else:
            channel = Channel.User
            db_command = UserCommand(enrolled_user=target)

        if not cls.verify_channel_and_device(channel, enrolled_device):
            raise ValueError("Incompatible channel or device")

        db_command.artifact_version = artifact_version
        db_command.kwargs = kwargs or {}

        # scheduling
        if not queue:
            if delay:
                raise ValueError("Cannot have a not-queued command with delay")
            db_command.not_before = None
            db_command.time = timezone.now()
        else:
            db_command.time = None
            if not delay:
                db_command.not_before = None
            else:
                db_command.not_before = timezone.now() + timedelta(seconds=delay)

        return cls(channel, db_command)

    @classmethod
    def create_for_device(cls, enrolled_device, artifact_version=None, kwargs=None, queue=False, delay=0):
        return cls.create_for_target(
            enrolled_device, enrolled_device,
            artifact_version, kwargs, queue, delay
        )

    @classmethod
    def create_for_user(cls, enrolled_user, artifact_version=None, kwargs=None, queue=False, delay=0):
        return cls.create_for_target(
            enrolled_user.enrolled_device, enrolled_user,
            artifact_version, kwargs, queue, delay
        )

    def load_kwargs(self):
        pass

    def __init__(self, channel, db_command):
        self.channel = channel
        self.status = None
        self.db_command = db_command
        if not self.db_command.pk:
            # new command
            self.db_command.uuid = self.uuid = uuid.uuid4()
            self.db_command.name = self.get_db_name()
            if self.artifact_operation:
                self.db_command.artifact_operation = self.artifact_operation.name
            self.db_command.save()
        elif self.db_command.status:
            self.uuid = self.db_command.uuid
            self.status = CommandStatus(self.db_command.status)
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
        # kwargs?
        self.load_kwargs()

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
        if self.db_command.result_time and (not self.reschedule_notnow or not self.status == CommandStatus.NotNow):
            logger.error("Command {self.db_command.uuid} has already been processed")
            return
        self.db_command.result_time = timezone.now()
        self.status = CommandStatus(response["Status"])
        self.db_command.status = self.status.value
        self.db_command.error_chain = response.get("ErrorChain")
        if self.store_result and self.status != CommandStatus.NotNow:
            self.db_command.result = plistlib.dumps(response)
        self.db_command.save()
        self.response = response
        self.enrollment_session = enrollment_session
        self.realm_user = enrollment_session.realm_user
        self.meta_business_unit = meta_business_unit
        if self.status == CommandStatus.Acknowledged:
            self.command_acknowledged()

    def command_acknowledged(self):
        pass

    def set_time(self):
        if self.db_command.time and not self.status == CommandStatus.NotNow:
            raise ValueError("Command {self.db_command.uuid} has time")
        self.db_command.time = timezone.now()
        self.db_command.save()


registered_commands = {}


def register_command(command_cls):
    registered_commands[command_cls.get_db_name()] = command_cls
