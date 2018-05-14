import logging
import plistlib
from django.http import HttpResponse
from django.views.generic import View
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.mdm.commands import build_device_information_command_response
from zentral.contrib.mdm.events import MDMRequestEvent
from zentral.contrib.mdm.models import (EnrolledDevice, EnrolledUser,
                                        DEPEnrollmentSession, OTAEnrollmentSession,
                                        PushCertificate)
from zentral.contrib.mdm.utils import parse_dn, tree_from_payload
from .base import PostEventMixin

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
                    .select_related("enrolled_device")
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except OTAEnrollmentSession.DoesNotExist:
                self.abort("Bad OTA enrollment session secret in client certificate CN")
        elif enrollment_type == "DEP":
            try:
                self.enrollment_session = (
                    DEPEnrollmentSession.objects
                    .select_related("enrolled_device")
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
        enrolled_device_defaults = {"push_certificate": self.push_certificate,
                                    "serial_number": self.serial_number,
                                    "token": None,
                                    "push_magic": None,
                                    "unlock_token": None}
        enrolled_device, created = EnrolledDevice.objects.update_or_create(udid=self.udid,
                                                                           defaults=enrolled_device_defaults)

        # update enrollment session
        self.enrollment_session.set_authenticated_status(enrolled_device)

        # post events
        if created:
            self.post_event("success", reenrollment=False)
        else:
            self.post_event("success", reenrollment=True)

    def do_token_update(self):
        # TODO: do something with AwaitingConfiguration. Part of the DEP setup.

        enrolled_device_defaults = {"push_certificate": self.push_certificate,
                                    "serial_number": self.serial_number,
                                    "push_magic": self.payload.get("PushMagic"),
                                    "unlock_token": self.payload.get("UnlockToken")}

        payload_token = self.payload.get("Token")

        user_id = self.payload.get("UserID")
        if not user_id:
            # payload token is the enrolled device token
            enrolled_device_defaults["token"] = payload_token

        # enrolled device
        enrolled_device, device_created = EnrolledDevice.objects.get_or_create(
            udid=self.udid,
            defaults=enrolled_device_defaults
        )

        updated_device_attr = []
        if not device_created:
            for attr, val in enrolled_device_defaults.items():
                current_val = getattr(enrolled_device, attr)
                if current_val != val:
                    setattr(enrolled_device, attr, val)
                    updated_device_attr.append(attr)
            if updated_device_attr:
                enrolled_device.save()
                updated_device_attr.sort()

        # Update enrollment session
        if enrolled_device.token and not self.enrollment_session.is_completed():
            self.enrollment_session.set_completed_status(enrolled_device)

        # enrolled user
        updated_user_attr = []
        user_created = False
        if user_id:
            enrolled_user_defaults = {"long_name": self.payload.get("UserLongName"),
                                      "short_name": self.payload.get("UserShortName"),
                                      "token": payload_token,
                                      "enrolled_device": enrolled_device}
            enrolled_user, user_created = EnrolledUser.objects.get_or_create(
                user_id=user_id,
                defaults=enrolled_user_defaults
            )
            if not user_created:
                for attr, val in enrolled_user_defaults.items():
                    current_val = getattr(enrolled_user, attr)
                    if current_val != val:
                        setattr(enrolled_device, attr, val)
                        updated_user_attr.append(attr)
                    if updated_user_attr:
                        enrolled_user.save()
                        updated_user_attr.sort()

        self.post_event("success",
                        token_type="user" if user_id else "device",
                        user_id=user_id,
                        device_created=device_created,
                        updated_device_attr=updated_device_attr,
                        user_created=user_created,
                        updated_user_attr=updated_user_attr)

    def do_checkout(self):
        # TODO: mark as gone
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
    def post_event(self, *args, **kwargs):
        if self.payload_status:
            kwargs["payload_status"] = self.payload_status
        super().post_event(*args, **kwargs)

    def do_idle(self):
        # TODO: QUICK AND DIRTY first command
        self.post_event("success")
        return build_device_information_command_response()

    def do_acknowledged(self):
        # TODO: QUICK AND DIRTY first command
        query_responses = self.payload.get("QueryResponses")
        if query_responses:
            commit_machine_snapshot_and_trigger_events(tree_from_payload(self.udid,
                                                                         self.serial_number,
                                                                         self.meta_business_unit,
                                                                         query_responses))

        self.post_event("success", command_uuid=self.payload["CommandUUID"])
        return HttpResponse()

    def do_error(self):
        self.post_event("failure")
        return HttpResponse()

    def do_command_format_error(self):
        self.post_event("failure")
        return HttpResponse()

    def do_not_now(self):
        self.post_event("success")
        return HttpResponse()

    def do_put(self):
        self.payload_status = self.payload["Status"]
        if self.payload_status == "Acknowledged":
            return self.do_acknowledged()
        elif self.payload_status == "Error":
            return self.do_error()
        elif self.payload_status == "CommandFormatError":
            return self.do_command_format_error()
        elif self.payload_status == "Idle":
            return self.do_idle()
        elif self.payload_status == "NotNow":
            return self.do_not_now()
        else:
            self.abort("unknown payload status")
