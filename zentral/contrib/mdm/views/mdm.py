import json
import logging
import plistlib
from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.core.files.storage import default_storage
from django.db import transaction
from django.http import FileResponse, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.functional import cached_property
from django.views.generic import View
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands.declarative_management import DeclarativeManagement
from zentral.contrib.mdm.commands.device_information import DeviceInformation
from zentral.contrib.mdm.commands.install_profile import build_payload
from zentral.contrib.mdm.commands.utils import get_command, get_next_command_response
from zentral.contrib.mdm.declarations import (build_legacy_profile,
                                              build_management_status_subscriptions,
                                              update_enrolled_device_artifacts)
from zentral.contrib.mdm.events import MDMRequestEvent
from zentral.contrib.mdm.inventory import commit_tree_from_payload
from zentral.contrib.mdm.models import (ArtifactType, ArtifactVersion,
                                        Channel, DeviceCommand, EnrolledDevice, EnrolledUser,
                                        DEPEnrollmentSession, OTAEnrollmentSession, UserEnrollmentSession,
                                        PushCertificate)
from zentral.contrib.mdm.tasks import send_enrolled_device_notification, send_enrolled_user_notification
from zentral.utils.certificates import parse_dn
from zentral.utils.storage import file_storage_has_signed_urls
from .base import PostEventMixin


logger = logging.getLogger('zentral.contrib.mdm.views.mdm')


class MDMView(PostEventMixin, View):
    event_class = MDMRequestEvent
    certificate = None
    push_certificate = None
    enrollment_session = None

    def post_event(self, *args, **kwargs):
        view_name = self.request.resolver_match.view_name
        if view_name:
            kwargs["view_name"] = view_name.split(":")[-1]
        if self.enrollment_session:
            kwargs.update(self.enrollment_session.serialize_for_event())
        super().post_event(*args, **kwargs)

    def dispatch(self, request, *args, **kwargs):
        # PostEventMixin
        self.setup_with_request(request)

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
        elif enrollment_type == "USER":
            try:
                self.enrollment_session = (
                    UserEnrollmentSession.objects
                    .select_for_update()
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except UserEnrollmentSession.DoesNotExist:
                self.abort("Bad user enrollment session secret in client certificate CN")
        else:
            self.abort("unknown MDM enrollment type {}".format(enrollment_type))

        # verify serial number
        self.serial_number = dn_d.get("serialNumber")
        if not self.serial_number and enrollment_type != "USER":
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
        return super().dispatch(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        # read payload
        self.payload = plistlib.loads(self.request.read())

        # IDs
        self.enrollment_id = self.payload.get("EnrollmentID")
        self.enrollment_user_id = self.payload.get("EnrollmentUserID")
        self.udid = self.payload.get("UDID")
        self.user_id = self.payload.get("UserID")

        if not self.serial_number:
            self.serial_number = self.enrollment_id
        self.enrolled_device_udid = self.udid or self.enrollment_id
        self.enrolled_user_id = self.user_id or self.enrollment_user_id
        if self.enrolled_user_id:
            self.channel = Channel.User
        else:
            self.channel = Channel.Device
        return self.do_put()

    def get_certificate(self):
        urlencoded_cert_pem = self.request.META.get("HTTP_X_SSL_CLIENT_CERT")
        if urlencoded_cert_pem:
            cert_pem = unquote(urlencoded_cert_pem)
            self.certificate = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        else:
            logger.warning("Empty X-SSL-Client-Cert header")

    def get_push_certificate(self):
        topic = self.payload.get("Topic")
        try:
            self.push_certificate = PushCertificate.objects.get(topic=topic)
        except PushCertificate.DoesNotExist:
            self.abort("unknown topic", topic=topic)

    def get_enrolled_device(self):
        enrolled_device = self.enrollment_session.enrolled_device
        if not enrolled_device:
            self.abort("enrollment session has no enrolled device")
        if enrolled_device.udid != self.enrolled_device_udid:
            # should never happen
            self.abort("enrollment session enrolled device UDID missmatch")
        return enrolled_device

    def get_enrolled_user(self):
        if self.channel == Channel.Device:
            return
        enrolled_device = self.get_enrolled_device()
        try:
            return (enrolled_device.enrolleduser_set.select_related("enrolled_device")
                                                    .get(user_id=self.enrolled_user_id))
        except EnrolledUser.DoesNotExist:
            self.abort(f"enrolled device {enrolled_device.udid} has no user {self.enrolled_user_id}")


class CheckinView(MDMView):
    message_type = None
    first_notification_delay = 5  # in seconds, TODO: empirical!!!

    def post_event(self, *args, **kwargs):
        if self.message_type:
            kwargs["message_type"] = self.message_type
        if self.push_certificate:
            kwargs["push_certificate"] = {"pk": self.push_certificate.pk,
                                          "topic": self.push_certificate.topic}
        super().post_event(*args, **kwargs)

    def do_authenticate(self):
        self.get_certificate()
        self.get_push_certificate()

        # commit machine infos
        ms_tree = commit_tree_from_payload(self.enrolled_device_udid,
                                           self.serial_number,
                                           self.meta_business_unit,
                                           self.payload)

        # save the enrolled device (NOT YET ENROLLED!)
        enrolled_device_defaults = {"enrollment_id": self.enrollment_id,
                                    "serial_number": self.serial_number,
                                    "push_certificate": self.push_certificate,
                                    "token": None,
                                    "push_magic": None,
                                    "unlock_token": None,
                                    "awaiting_configuration": None,
                                    "checkout_at": None}
        try:
            os_name = ms_tree["os_version"]["name"]
        except KeyError:
            pass
        else:
            enrolled_device_defaults["platform"] = os_name
        if self.certificate:
            enrolled_device_defaults.update({
                "cert_fingerprint": self.certificate.fingerprint(hashes.SHA256()),
                "cert_not_valid_after": self.certificate.not_valid_after,
            })
        enrolled_device, created = EnrolledDevice.objects.update_or_create(udid=self.enrolled_device_udid,
                                                                           defaults=enrolled_device_defaults)

        # purge the installed artifacts and sent commands, to start from scratch
        if not created:
            # TODO do not purge if renewal
            enrolled_device.purge_state()

        # schedule a DeviceInformation command
        DeviceInformation.create_for_device(enrolled_device, queue=True)
        # switch on declarative management if possible
        if DeclarativeManagement.verify_channel_and_device(Channel.Device, enrolled_device):
            DeclarativeManagement.create_for_device(enrolled_device, queue=True)

        # update enrollment session
        self.enrollment_session.set_authenticated_status(enrolled_device)

        # post events
        if created:
            self.post_event("success", reenrollment=False)
        else:
            self.post_event("success", reenrollment=True)

    def do_token_update(self):
        self.get_push_certificate()
        awaiting_configuration = self.payload.get("AwaitingConfiguration", False)
        enrolled_device_defaults = {"enrollment_id": self.enrollment_id,
                                    "blueprint": self.enrollment_session.get_blueprint(),
                                    "awaiting_configuration": awaiting_configuration,
                                    "serial_number": self.serial_number,
                                    "push_certificate": self.push_certificate,
                                    "push_magic": self.payload.get("PushMagic"),
                                    "checkout_at": None}

        # UnlockToken can be absent, and must not be deleted
        unlock_token = self.payload.get("UnlockToken")
        if unlock_token:
            enrolled_device_defaults["unlock_token"] = unlock_token

        payload_token = self.payload.get("Token")

        if self.channel == Channel.Device:
            # payload token is the enrolled device token
            enrolled_device_defaults["token"] = payload_token

        # enrolled device
        enrolled_device, device_created = EnrolledDevice.objects.update_or_create(
            udid=self.enrolled_device_udid,
            defaults=enrolled_device_defaults
        )

        # send first push notifications
        if self.channel == Channel.Device and enrolled_device.can_be_poked():
            transaction.on_commit(lambda: send_enrolled_device_notification(
                enrolled_device,
                delay=self.first_notification_delay
            ))

        # Update enrollment session
        if enrolled_device.token and not self.enrollment_session.is_completed():
            self.enrollment_session.set_completed_status(enrolled_device)

        # enrolled user
        user_created = False
        if self.channel == Channel.User and self.enrolled_user_id.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
            # user channel and no shared ipad
            # see https://developer.apple.com/documentation/devicemanagement/tokenupdaterequest
            enrolled_user_defaults = {"enrolled_device": enrolled_device,
                                      "enrollment_id": self.enrollment_user_id,
                                      "long_name": self.payload.get("UserLongName"),
                                      "short_name": self.payload.get("UserShortName"),
                                      "token": payload_token}
            enrolled_user, user_created = EnrolledUser.objects.update_or_create(
                user_id=self.enrolled_user_id,
                defaults=enrolled_user_defaults
            )
            transaction.on_commit(lambda: send_enrolled_user_notification(
                enrolled_user,
                delay=self.first_notification_delay
            ))
        self.post_event("success",
                        token_type="user" if self.channel == Channel.User else "device",
                        user_id=self.enrolled_user_id,
                        device_created=device_created,
                        user_created=user_created)

    def do_set_bootstrap_token(self):
        # https://developer.apple.com/documentation/devicemanagement/setbootstraptokenrequest
        enrolled_device = self.get_enrolled_device()
        enrolled_device.awaiting_configuration = self.payload.get("AwaitingConfiguration", False)
        enrolled_device.bootstrap_token = self.payload.get("BootstrapToken", None)
        enrolled_device.save()
        self.post_event("success")

    def do_get_bootstrap_token(self):
        # https://developer.apple.com/documentation/devicemanagement/get_bootstrap_token
        enrolled_device = self.get_enrolled_device()
        if not enrolled_device.bootstrap_token:
            self.abort(f"Enrolled device {enrolled_device.udid} has no bootstrap token")
        else:
            self.post_event("success")
            return HttpResponse(plistlib.dumps({"BootstrapToken": enrolled_device.bootstrap_token.tobytes()}),
                                content_type="application/xml")

    def do_declarative_management(self):
        # https://developer.apple.com/documentation/devicemanagement/declarativemanagementrequest
        endpoint = self.payload.get("Endpoint")
        event_payload = {"endpoint": endpoint}
        data = self.payload.get("Data")
        if data:
            json_data = json.loads(data)
            event_payload["data"] = json_data
        enrolled_device = self.get_enrolled_device()
        blueprint = enrolled_device.blueprint
        if not blueprint:
            # TODO default empty configuration?
            self.abort("Missing blueprint. No declarative management possible.", **event_payload)
        if endpoint == "tokens":
            logger.warning("Declarative management tokens endpoint not implemented")
            response = {}
        elif endpoint == "declaration-items":
            response = blueprint.declaration_items
        elif endpoint == "status":
            update_enrolled_device_artifacts(enrolled_device, json_data)
            self.post_event("success", **event_payload)
            return HttpResponse(status=204)
        elif endpoint.startswith("declaration"):
            _, declaration_type, declaration_identifier = endpoint.split("/")
            event_payload["declaration_type"] = declaration_type
            event_payload["declaration_identifier"] = declaration_identifier
            if declaration_identifier.endswith("management-status-subscriptions"):
                response = build_management_status_subscriptions(blueprint)
            elif declaration_identifier.endswith("activation"):
                response = blueprint.activation
            elif "legacy-profile" in declaration_identifier:
                response = build_legacy_profile(blueprint, declaration_identifier)
            else:
                self.abort("Unknown declaration", **event_payload)
        self.post_event("success", **event_payload)
        return JsonResponse(response)

    def do_checkout(self):
        enrolled_device = self.get_enrolled_device()
        enrolled_device.do_checkout()
        self.post_event("success")

    def do_put(self):
        self.message_type = self.payload.get("MessageType")

        # route the payload
        if self.message_type == "Authenticate":
            self.do_authenticate()
        elif self.message_type == "UserAutenticate":
            # TODO: network / mobile user management
            self.post_event("warning", user_id=self.enrolled_user_id)
            return HttpResponse(status=410)
        elif self.message_type == "TokenUpdate":
            self.do_token_update()
        elif self.message_type == "SetBootstrapToken":
            self.do_set_bootstrap_token()
        elif self.message_type == "GetBootstrapToken":
            return self.do_get_bootstrap_token()
        elif self.message_type == "DeclarativeManagement":
            return self.do_declarative_management()
        elif self.message_type == "CheckOut":
            self.do_checkout()
        else:
            self.abort("unknown message type")

        return HttpResponse()


class ConnectView(MDMView):
    def do_put(self):
        command_uuid = self.payload.get("CommandUUID", None)
        payload_status = self.payload["Status"]
        self.post_event("failure" if payload_status in ("Error", "CommandFormatError") else "success",
                        command_uuid=command_uuid,
                        payload_status=payload_status,
                        user_id=self.enrolled_user_id)

        # result
        if payload_status != "Idle":
            command = get_command(self.channel, command_uuid)
            if command:
                command.process_response(self.payload, self.enrollment_session, self.meta_business_unit)
        if payload_status in ["Idle", "Acknowledged", "Error", "CommandFormatError"]:
            # we can send another command
            return get_next_command_response(self.channel, self.enrollment_session,
                                             self.get_enrolled_device(), self.get_enrolled_user())
        elif payload_status in ["NotNow"]:
            # we let the device contact us again
            # TODO implement another strategy
            return HttpResponse()
        else:
            self.abort("unknown payload status {}".format(payload_status))


class EnterpriseAppDownloadView(View):
    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, response, *args, **kwargs):
        # TODO limit access
        # TODO DownloadEnterpriseAppEvent with mdm namespace
        device_command = get_object_or_404(DeviceCommand.objects.select_related("artifact_version__enterprise_app"),
                                           name="InstallEnterpriseApplication", uuid=kwargs["uuid"])
        package_file = device_command.artifact_version.enterprise_app.package
        if self._redirect_to_files:
            return HttpResponseRedirect(default_storage.url(package_file.name))
        else:
            return FileResponse(default_storage.open(package_file.name), as_attachment=True)


class ProfileDownloadView(MDMView):
    def get(self, response, *args, **kwargs):
        # TODO limit access
        # TODO DownloadProfileEvent with mdm namespace
        artifact_version = get_object_or_404(
            ArtifactVersion.objects.select_related("profile"),
            pk=kwargs["pk"],
            artifact__type=ArtifactType.Profile.name
        )
        return HttpResponse(build_payload(artifact_version.profile, self.enrollment_session),
                            content_type="application/x-apple-aspen-config")
