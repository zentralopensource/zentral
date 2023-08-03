from datetime import timedelta
import logging
import plistlib
from uuid import uuid4
from django import forms
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.models import Channel, Command as DBCommand, DeviceCommand, UserCommand


logger = logging.getLogger("zentral.contrib.mdm.commands.base")


class Command:
    request_type = None
    db_name = None
    display_name = None
    artifact_operation = None
    store_result = False
    reschedule_notnow = False
    form_class = None

    @classmethod
    def get_db_name(cls):
        return cls.db_name or cls.request_type

    @classmethod
    def get_display_name(cls):
        return cls.display_name or cls.get_db_name()

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        raise NotImplementedError

    @classmethod
    def verify_target(cls, target):
        return cls.verify_channel_and_device(target.channel, target.enrolled_device)

    @classmethod
    def create_for_target(
        cls,
        target,
        artifact_version=None,
        kwargs=None,
        queue=False, delay=0,
        uuid=None,
    ):
        if not cls.verify_target(target):
            raise ValueError("Incompatible channel or device")

        # DB command
        db_command_model, db_command_kwargs = target.get_db_command_model_and_kwargs()
        db_command = db_command_model(**db_command_kwargs)
        db_command.artifact_version = artifact_version
        db_command.kwargs = kwargs or {}

        # DB command scheduling
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

        return cls(target.channel, db_command, uuid)

    @classmethod
    def create_for_device(cls, enrolled_device, artifact_version=None, kwargs=None, queue=False, delay=0, uuid=None):
        return cls.create_for_target(Target(enrolled_device), artifact_version, kwargs, queue, delay, uuid)

    def load_kwargs(self):
        pass

    def __init__(self, channel, db_command, uuid=None):
        self.channel = channel
        self.response = None
        self.result_time = None
        self.status = None
        self.db_command = db_command
        if not self.db_command.pk:
            # new command
            self.uuid = uuid
            if not self.uuid:
                self.uuid = uuid4()
            self.db_command.uuid = self.uuid
            self.db_command.name = self.get_db_name()
            if self.artifact_operation:
                self.db_command.artifact_operation = self.artifact_operation.name
            self.db_command.save()
        else:
            self.uuid = self.db_command.uuid
            if self.db_command.status:
                if self.db_command.result:
                    self.response = plistlib.loads(self.db_command.result)
                self.result_time = self.db_command.result_time
                self.status = DBCommand.Status(self.db_command.status)
        # enrolled objects
        self.enrolled_device = getattr(db_command, "enrolled_device", None)
        self.enrolled_user = getattr(db_command, "enrolled_user", None)
        if self.enrolled_user:
            self.enrolled_device = self.enrolled_user.enrolled_device
        self.target = Target(self.enrolled_device, self.enrolled_user)
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
        if self.db_command.result_time and (not self.reschedule_notnow or not self.status == DBCommand.Status.NOT_NOW):
            logger.error("Command %s has already been processed", self.uuid)
            return
        self.result_time = self.db_command.result_time = timezone.now()
        self.status = DBCommand.Status(response["Status"])
        self.db_command.status = self.status
        self.db_command.error_chain = response.get("ErrorChain")
        if self.store_result and self.status != DBCommand.Status.NOT_NOW:
            self.db_command.result = plistlib.dumps(response, fmt=plistlib.FMT_BINARY)
        self.db_command.save()
        self.response = response
        self.enrollment_session = enrollment_session
        self.realm_user = enrollment_session.realm_user
        self.meta_business_unit = meta_business_unit
        if self.status == DBCommand.Status.ACKNOWLEDGED:
            self.command_acknowledged()
        elif self.status == DBCommand.Status.ERROR:
            self.command_error()

    def command_acknowledged(self):
        pass

    def command_error(self):
        pass

    def set_time(self):
        if self.db_command.time and not self.status == DBCommand.Status.NOT_NOW:
            raise ValueError("Command {self.db_command.uuid} has time")
        self.db_command.time = timezone.now()
        self.db_command.save()


registered_commands = {}
registered_manual_commands = {}


def register_command(command_cls):
    key = command_cls.get_db_name()
    registered_commands[key] = command_cls
    if command_cls.form_class:
        registered_manual_commands[key] = command_cls


def load_command(db_command):
    try:
        model_class = registered_commands[db_command.name]
    except KeyError:
        raise ValueError(f"Unknown command model class: {db_command.name}")
    if isinstance(db_command, DeviceCommand):
        return model_class(Channel.DEVICE, db_command)
    else:
        return model_class(Channel.USER, db_command)


def get_command(channel, uuid):
    if channel == Channel.DEVICE:
        db_model_class = DeviceCommand
    else:
        db_model_class = UserCommand
    try:
        db_command = (db_model_class.objects.select_related("artifact_version__artifact",
                                                            "artifact_version__enterprise_app",
                                                            "artifact_version__profile",
                                                            "artifact_version__store_app__location_asset__asset",
                                                            "artifact_version__store_app__location_asset__location")
                                            .get(uuid=uuid))
    except db_model_class.DoesNotExist:
        logger.error("Unknown command: %s %s", channel, uuid)
        return
    return load_command(db_command)


class CommandBaseForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.channel = kwargs.pop("channel")
        self.enrolled_device = kwargs.pop("enrolled_device")
        self.enrolled_user = kwargs.pop("enrolled_user", None)
        super().__init__(*args, **kwargs)

    def get_command_kwargs(self, uuid):
        return {}
