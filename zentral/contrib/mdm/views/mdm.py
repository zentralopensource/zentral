import logging
import plistlib
from django.db import transaction
from django.http import HttpResponse
from django.views.generic import View
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.mdm.commands import queue_account_configuration_command_if_needed
from zentral.contrib.mdm.events import MDMRequestEvent
from zentral.contrib.mdm.models import (EnrolledDevice, EnrolledUser,
                                        DEPEnrollmentSession, OTAEnrollmentSession,
                                        PushCertificate)
from zentral.contrib.mdm.tasks import send_enrolled_device_notification
from zentral.utils.certificates import parse_dn
from .base import PostEventMixin
from .utils import (build_application_download_response, build_application_manifest_response,
                    get_next_device_command_response,
                    process_result_payload, tree_from_payload)

logger = logging.getLogger('zentral.contrib.mdm.views.mdm')


class MDMView(PostEventMixin, View):
    event_class = MDMRequestEvent
    push_certificate = None
    enrollment_session = None

    def post_event(self, *args, **kwargs):
        view_name = self.request.resolver_match.view_name
        if view_name:
            kwargs["view_name"] = view_name.split(":")[-1]
        if self.enrollment_session:
            kwargs.update(self.enrollment_session.serialize_for_event())
        super().post_event(*args, **kwargs)

    def put(self, request, *args, **kwargs):
        # DN => serial_number + meta_business_unit
        dn = request.META.get("HTTP_X_SSL_CLIENT_S_DN")
        if not dn:
            self.abort("missing DN in request headers")

        dn_d = parse_dn(dn)

        cn = dn_d.get("CN")
        try:
            cn_prefix, enrollment_type, enrollment_secret_secret = cn.split("$")
        except (AttributeError, ValueError):
            self.abort("missing or bad CN in client certificate DN")

        # verify prefix
        if cn_prefix != "MDM":
            self.abort("bad CN prefix in client certificate")

        # verify enrollment
        if enrollment_type == "OTA":
            try:
                self.enrollment_session = (
                    OTAEnrollmentSession.objects
                    .select_for_update()
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except OTAEnrollmentSession.DoesNotExist:
                self.abort("Bad OTA enrollment session secret in client certificate CN")
        elif enrollment_type == "DEP":
            try:
                self.enrollment_session = (
                    DEPEnrollmentSession.objects
                    .select_for_update()
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except DEPEnrollmentSession.DoesNotExist:
                self.abort("Bad DEP enrollment session secret in client certificate CN")
        else:
            self.abort("unknown MDM enrollment type {}".format(enrollment_type))

        # verify serial number
        self.serial_number = dn_d.get("serialNumber")
        if not self.serial_number:
            self.abort("empty serial number in client certificate CN")

        # verify meta business unit
        o = dn_d.get("O")
        if not o or not o.startswith("MBU$"):
            self.abort("missing or bad O in client certificate DN")
        else:
            try:
                mbu_pk = int(o[4:])
                self.meta_business_unit = MetaBusinessUnit.objects.get(pk=mbu_pk)
            except (MetaBusinessUnit.DoesNotExist, ValueError):
                self.abort("unknown meta business unit in client certificate DN")

        # read payload
        self.payload = plistlib.loads(self.request.read())
        self.udid = self.payload.get("UDID")
        return self.do_put()


class CheckinView(MDMView):
    message_type = None
    first_device_notification_delay = 5  # in seconds, TODO: empirical!!!

    def post_event(self, *args, **kwargs):
        if self.message_type:
            kwargs["message_type"] = self.message_type
        if self.push_certificate:
            kwargs["push_certificate"] = {"pk": self.push_certificate.pk,
                                          "topic": self.push_certificate.topic}
        super().post_event(*args, **kwargs)

    def do_authenticate(self):
        # commit machine infos
        self.commit_tree()

        # save the enrolled device (NOT YET ENROLLED!)
        enrolled_device_defaults = {"enrollment_id": self.payload.get("EnrollmentID"),
                                    "awaiting_configuration": None,
                                    "serial_number": self.serial_number,
                                    "push_certificate": self.push_certificate,
                                    "token": None,
                                    "push_magic": None,
                                    "unlock_token": None,
                                    "checkout_at": None}
        enrolled_device, created = EnrolledDevice.objects.update_or_create(udid=self.udid,
                                                                           defaults=enrolled_device_defaults)

        # purge the installed artifacts and sent commands, to start from scratch
        enrolled_device.purge_state()

        # update enrollment session
        self.enrollment_session.set_authenticated_status(enrolled_device)

        # post events
        if created:
            self.post_event("success", reenrollment=False)
        else:
            self.post_event("success", reenrollment=True)

    def do_token_update(self):
        # TODO: do something with AwaitingConfiguration. Part of the DEP setup.
        awaiting_configuration = self.payload.get("AwaitingConfiguration", False)
        enrolled_device_defaults = {"enrollment_id": self.payload.get("EnrollmentID"),
                                    "awaiting_configuration": awaiting_configuration,
                                    "serial_number": self.serial_number,
                                    "push_certificate": self.push_certificate,
                                    "push_magic": self.payload.get("PushMagic"),
                                    "unlock_token": self.payload.get("UnlockToken"),
                                    "checkout_at": None}

        payload_token = self.payload.get("Token")

        user_id = self.payload.get("UserID")
        if not user_id:
            # payload token is the enrolled device token
            enrolled_device_defaults["token"] = payload_token

        # enrolled device
        enrolled_device, device_created = EnrolledDevice.objects.update_or_create(
            udid=self.udid,
            defaults=enrolled_device_defaults
        )

        # accounts creation
        if awaiting_configuration:
            dep_profile = getattr(self.enrollment_session, "dep_profile", None)
            if dep_profile:
                queue_account_configuration_command_if_needed(
                    enrolled_device,
                    dep_profile,
                    self.enrollment_session.realm_user
                )
            else:
                # should never happen. AwaitingConfiguration is only used during DEP enrollments
                logger.error("AwaitingConfiguration but not a DEP enrollment session ???")

        # send first push notifications
        if not user_id and enrolled_device.can_be_poked():
            transaction.on_commit(lambda: send_enrolled_device_notification(
                enrolled_device,
                delay=self.first_device_notification_delay
            ))
            transaction.on_commit(lambda: send_enrolled_device_notification(
                enrolled_device,
                delay=2 * self.first_device_notification_delay
            ))

        # Update enrollment session
        if enrolled_device.token and not self.enrollment_session.is_completed():
            self.enrollment_session.set_completed_status(enrolled_device)

        # enrolled user
        user_created = False
        if user_id and user_id.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
            # user channel and no shared ipad
            # see https://developer.apple.com/documentation/devicemanagement/tokenupdaterequest
            enrolled_user_defaults = {"enrolled_device": enrolled_device,
                                      "enrollment_id": self.payload.get("EnrollmentUserID"),
                                      "long_name": self.payload.get("UserLongName"),
                                      "short_name": self.payload.get("UserShortName"),
                                      "token": payload_token}
            enrolled_user, user_created = EnrolledUser.objects.update_or_create(
                user_id=user_id,
                defaults=enrolled_user_defaults
            )

        self.post_event("success",
                        token_type="user" if user_id else "device",
                        user_id=user_id,
                        device_created=device_created,
                        user_created=user_created)

    def do_checkout(self):
        try:
            enrolled_device = EnrolledDevice.objects.get(push_certificate=self.push_certificate,
                                                         udid=self.udid)
        except EnrolledDevice.DoesNotExist:
            self.abort("Could not do checkout. Unknown enrolled device",
                       push_certificate_topic=self.push_certificate.topic,
                       device_udid=self.udid)
        else:
            enrolled_device.do_checkout()
            self.post_event("success")

    def commit_tree(self):
        commit_machine_snapshot_and_trigger_events(tree_from_payload(self.udid,
                                                                     self.serial_number,
                                                                     self.meta_business_unit,
                                                                     self.payload))

    def do_put(self):
        self.message_type = self.payload.get("MessageType")
        self.push_certificate = None

        # get push certificate
        topic = self.payload.get("Topic")
        try:
            self.push_certificate = PushCertificate.objects.get(topic=topic)
        except PushCertificate.DoesNotExist:
            self.abort("unknown topic", topic=topic)

        # route the payload
        if self.message_type == "Authenticate":
            self.do_authenticate()
        elif self.message_type == "UserAutenticate":
            # TODO: network / mobile user management
            self.post_event("warning", user_id=self.payload.get("UserID"))
            return HttpResponse(status_code=410)
        elif self.message_type == "TokenUpdate":
            self.do_token_update()
        elif self.message_type == "CheckOut":
            self.do_checkout()
        else:
            self.abort("unknown message type")

        return HttpResponse()


class ConnectView(MDMView):
    @staticmethod
    def get_success(payload_status):
        if payload_status in ["Error", "CommandFormatError"]:
            return "failure"
        else:
            return "success"

    def do_put(self):
        command_uuid = self.payload.get("CommandUUID", None)
        payload_status = self.payload["Status"]
        user_id = self.payload.get("UserID")
        self.post_event(self.get_success(payload_status),
                        command_uuid=command_uuid,
                        payload_status=payload_status,
                        user_id=user_id)

        enrolled_device = self.enrollment_session.enrolled_device

        # result
        if payload_status != "Idle":
            process_result_payload(self.meta_business_unit, enrolled_device,
                                   command_uuid, payload_status,
                                   self.payload)

        # response
        if user_id:
            # TODO: do something!!!
            return HttpResponse()
        elif payload_status in ["Idle", "Acknowledged", "Error", "CommandFormatError"]:
            # we can send another command
            return get_next_device_command_response(self.meta_business_unit, enrolled_device)
        elif payload_status in ["NotNow"]:
            # we let the device contact us again
            return HttpResponse()
        else:
            self.abort("unknown payload status {}".format(payload_status))


class InstallApplicationManifestView(View):
    def get(self, response, *args, **kwargs):
        return build_application_manifest_response(kwargs["uuid"])


class InstallApplicationDownloadView(View):
    def get(self, response, *args, **kwargs):
        return build_application_download_response(kwargs["uuid"])
