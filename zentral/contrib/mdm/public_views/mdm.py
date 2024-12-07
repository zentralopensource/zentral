import base64
import json
import logging
import plistlib
from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.core.files.storage import default_storage
from django.http import FileResponse, Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.functional import cached_property
from django.views.generic import View
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands.install_profile import build_payload
from zentral.contrib.mdm.commands.base import get_command
from zentral.contrib.mdm.commands.scheduling import get_next_command_response
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.declarations import (build_declaration_response,
                                              load_data_asset_token,
                                              load_legacy_profile_token,
                                              DeclarationError)
from zentral.contrib.mdm.events import MDMRequestEvent
from zentral.contrib.mdm.inventory import ms_tree_from_payload, update_realm_user_machine_tags, MachineTag
from zentral.contrib.mdm.models import (ArtifactVersion,
                                        Channel, RequestStatus, DeviceCommand, EnrolledDevice, EnrolledUser,
                                        DEPEnrollmentSession, OTAEnrollmentSession,
                                        Platform,
                                        ReEnrollmentSession, UserEnrollmentSession,
                                        PushCertificate)
from zentral.utils.certificates import parse_dn
from zentral.utils.storage import file_storage_has_signed_urls
from .base import PostEventMixin


logger = logging.getLogger('zentral.contrib.mdm.public_views.mdm')


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

        header_signature = request.META.get("HTTP_MDM_SIGNATURE")
        if header_signature:
            try:
                certs, raw_payload = verify_signed_payload(request.body, base64.b64decode(header_signature))
            except Exception:
                self.abort("Invalid header signature")
            try:
                self.payload = plistlib.loads(raw_payload)
            except plistlib.InvalidFileException:
                self.payload = {}
            _, _, self.certificate = certs[0]
            subject = self.certificate.subject
            cert_cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            cert_o = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            self.serial_number = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        else:
            # mTLS with certificate subject in header
            # DN => serial_number + meta_business_unit
            dn = request.META.get("HTTP_X_SSL_CLIENT_S_DN")
            if not dn:
                self.abort("missing DN in request headers")
            try:
                self.payload = plistlib.loads(request.body)
            except plistlib.InvalidFileException:
                self.payload = {}
            dn_d = parse_dn(dn)
            cert_cn = dn_d.get("CN")
            cert_o = dn_d.get("O")
            self.serial_number = dn_d.get("serialNumber")

        # CN info
        try:
            cn_prefix, enrollment_type, enrollment_secret_secret = cert_cn.split("$")
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
                    .select_related("ota_enrollment")
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except OTAEnrollmentSession.DoesNotExist:
                self.abort("Bad OTA enrollment session secret in client certificate CN")
        elif enrollment_type == "DEP":
            try:
                self.enrollment_session = (
                    DEPEnrollmentSession.objects
                    .select_for_update()
                    .select_related("dep_enrollment")
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except DEPEnrollmentSession.DoesNotExist:
                self.abort("Bad DEP enrollment session secret in client certificate CN")
        elif enrollment_type == "RE":
            try:
                self.enrollment_session = (
                    ReEnrollmentSession.objects
                    .select_for_update()
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except ReEnrollmentSession.DoesNotExist:
                self.abort("Bad re-enrollment session secret in client certificate CN")
        elif enrollment_type == "USER":
            try:
                self.enrollment_session = (
                    UserEnrollmentSession.objects
                    .select_for_update()
                    .select_related("user_enrollment")
                    .get(enrollment_secret__secret=enrollment_secret_secret)
                )
            except UserEnrollmentSession.DoesNotExist:
                self.abort("Bad user enrollment session secret in client certificate CN")
        else:
            self.abort("unknown MDM enrollment type {}".format(enrollment_type))

        # verify serial number
        if not self.serial_number and enrollment_type != "USER":
            self.abort("empty serial number in client certificate CN")

        # verify meta business unit
        if not cert_o or not cert_o.startswith("MBU$"):
            self.abort("missing or bad O in client certificate DN")
        else:
            try:
                mbu_pk = int(cert_o[4:])
                self.meta_business_unit = MetaBusinessUnit.objects.get(pk=mbu_pk)
            except (MetaBusinessUnit.DoesNotExist, ValueError):
                self.abort("unknown meta business unit in client certificate DN")
        return super().dispatch(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
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
            self.channel = Channel.USER
        else:
            self.channel = Channel.DEVICE
        return self.do_put()

    def get_certificate(self):
        if self.certificate is None:
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

    @cached_property
    def enrolled_device(self):
        enrolled_device = self.enrollment_session.enrolled_device
        if not enrolled_device:
            self.abort("enrollment session has no enrolled device")
        if enrolled_device.udid != self.enrolled_device_udid:
            # should never happen
            self.abort("enrollment session enrolled device UDID missmatch")
        return enrolled_device

    @cached_property
    def enrolled_user(self):
        if self.channel == Channel.DEVICE:
            return
        enrolled_device = self.enrolled_device
        try:
            return (enrolled_device.enrolleduser_set.select_related("enrolled_device")
                                                    .get(user_id=self.enrolled_user_id))
        except EnrolledUser.DoesNotExist:
            self.abort(f"enrolled device {enrolled_device.udid} has no user {self.enrolled_user_id}")

    @cached_property
    def target(self):
        return Target(self.enrolled_device, self.enrolled_user)


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
        self.get_certificate()
        self.get_push_certificate()

        # save the enrolled device (NOT YET ENROLLED!)
        enrolled_device_defaults = {"enrollment_id": self.enrollment_id,
                                    "serial_number": self.serial_number,
                                    "push_certificate": self.push_certificate,
                                    "os_version": self.payload.get("OSVersion"),
                                    "token": None,
                                    "push_magic": None,
                                    "unlock_token": None,
                                    "awaiting_configuration": None,
                                    "checkout_at": None}
        ms_tree = ms_tree_from_payload(self.payload)
        platform = None
        try:
            platform = ms_tree["os_version"]["name"]
        except KeyError:
            pass
        else:
            enrolled_device_defaults["platform"] = platform
        if isinstance(self.enrollment_session, DEPEnrollmentSession):
            enrolled_device_defaults["dep_enrollment"] = True
            enrolled_device_defaults["user_enrollment"] = False
            enrolled_device_defaults["supervised"] = True
            if platform == Platform.MACOS:
                enrolled_device_defaults["user_approved_enrollment"] = True
        elif isinstance(self.enrollment_session, OTAEnrollmentSession):
            enrolled_device_defaults["dep_enrollment"] = False
            enrolled_device_defaults["user_enrollment"] = False
        elif isinstance(self.enrollment_session, UserEnrollmentSession):
            enrolled_device_defaults["dep_enrollment"] = False
            enrolled_device_defaults["user_enrollment"] = True
            enrolled_device_defaults["supervised"] = False
        if self.certificate:
            enrolled_device_defaults.update({
                "cert_fingerprint": self.certificate.fingerprint(hashes.SHA256()),
                "cert_not_valid_after": self.certificate.not_valid_after,
            })
        enrolled_device, created = EnrolledDevice.objects.update_or_create(udid=self.enrolled_device_udid,
                                                                           defaults=enrolled_device_defaults)

        is_reenrollment = isinstance(self.enrollment_session, ReEnrollmentSession)

        # purge the installed artifacts and sent commands, if it is not a re-enrollment
        if not created and not is_reenrollment:
            enrolled_device.purge_state(full=True)

        # initial machine tagging
        if not is_reenrollment:
            # enrollment tags
            enrollment_tags = list(self.enrollment_session.enrollment_secret.tags.all())
            if enrollment_tags:
                MachineTag.objects.bulk_create((
                    MachineTag(serial_number=self.serial_number, tag=enrollment_tag)
                    for enrollment_tag in enrollment_tags
                ), ignore_conflicts=True)
            # realm group tag mappings
            if self.enrollment_session.realm_user:
                update_realm_user_machine_tags(self.enrollment_session.realm_user, self.serial_number)

        # update enrollment session
        self.enrollment_session.set_authenticated_status(enrolled_device)

        # post event
        self.post_event("success", new_enrolled_device=created, reenrollment=is_reenrollment)

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

        payload_token = self.payload.get("Token")

        if self.channel == Channel.DEVICE:
            # payload token is the enrolled device token
            enrolled_device_defaults["token"] = payload_token

        # enrolled device
        enrolled_device, device_created = EnrolledDevice.objects.update_or_create(
            udid=self.enrolled_device_udid,
            defaults=enrolled_device_defaults
        )
        # UnlockToken can be absent, and must not be deleted
        unlock_token = self.payload.get("UnlockToken")
        if unlock_token:
            enrolled_device.set_unlock_token(unlock_token)
            enrolled_device.save()

        # Update enrollment session
        if enrolled_device.token and not self.enrollment_session.is_completed():
            self.enrollment_session.set_completed_status(enrolled_device)

        # enrolled user
        user_created = False
        if self.channel == Channel.USER and self.enrolled_user_id.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
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
        self.post_event("success",
                        token_type="user" if self.channel == Channel.USER else "device",
                        user_id=self.enrolled_user_id,
                        device_created=device_created,
                        user_created=user_created)

    def do_set_bootstrap_token(self):
        # https://developer.apple.com/documentation/devicemanagement/setbootstraptokenrequest
        self.enrolled_device.awaiting_configuration = self.payload.get("AwaitingConfiguration", False)
        self.enrolled_device.set_bootstrap_token(self.payload.get("BootstrapToken", None))
        self.enrolled_device.save()
        self.post_event("success")

    def do_get_bootstrap_token(self):
        # https://developer.apple.com/documentation/devicemanagement/get_bootstrap_token
        bootstrap_token = self.enrolled_device.get_bootstrap_token()
        event_payload = {}
        if not bootstrap_token:
            status = "warning"
            event_payload["reason"] = f"Enrolled device {self.enrolled_device.udid} has no bootstrap token"
            # see https://developer.apple.com/documentation/devicemanagement/get_bootstrap_token
            # """If no bootstrap token is available, the server should return empty or no data and no error."""
            bootstrap_token = b""
        else:
            status = "success"
        self.post_event(status, **event_payload)
        return HttpResponse(plistlib.dumps({"BootstrapToken": bootstrap_token}),
                            content_type="application/xml")

    def do_declarative_management(self):
        # https://developer.apple.com/documentation/devicemanagement/declarativemanagementrequest
        endpoint = self.payload.get("Endpoint")
        event_payload = {"endpoint": endpoint}
        data = self.payload.get("Data")
        if data:
            json_data = json.loads(data)
            event_payload["data"] = json_data
        blueprint = self.enrolled_device.blueprint
        if not blueprint:
            # TODO default empty configuration?
            self.abort("Missing blueprint. No declarative management possible.", **event_payload)
        if endpoint == "tokens":
            response, declarations_token = self.target.sync_tokens
            self.target.update_declarations_token(declarations_token)
        elif endpoint == "declaration-items":
            response = self.target.declaration_items
        elif endpoint == "status":
            self.target.update_target_with_status_report(json_data)
            self.post_event("success", **event_payload)
            return HttpResponse(status=204)
        elif endpoint.startswith("declaration/"):
            try:
                response = build_declaration_response(endpoint, event_payload, self.enrollment_session, self.target)
            except DeclarationError as e:
                self.abort(str(e), **event_payload)
        self.post_event("success", **event_payload)
        return JsonResponse(response)

    def do_checkout(self):
        self.enrolled_device.do_checkout()
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
        try:
            request_status = RequestStatus(self.payload["Status"])
        except KeyError:
            self.abort("missing request status")
        except ValueError:
            self.abort("unknown request status")
        command_uuid = self.payload.get("CommandUUID", None)

        self.post_event("failure" if request_status.is_error else "success",
                        command_uuid=command_uuid,
                        request_status=request_status.value,
                        user_id=self.enrolled_user_id)

        # result
        if command_uuid:
            command = get_command(self.channel, command_uuid)
            if command:
                command.process_response(self.payload, self.enrollment_session, self.meta_business_unit)

        # update last seen at
        self.target.update_last_seen()

        if self.target.blocked:
            return HttpResponse("Blocked", status=401)

        # return next command if possible
        return get_next_command_response(self.target, self.enrollment_session, request_status)


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


# DDM


class DataAssetDownloadView(View):
    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, response, *args, **kwargs):
        # TODO DownloadDataAssetEvent with mdm namespace
        try:
            data_asset, enrollment_session, enrolled_user = load_data_asset_token(kwargs["token"])
        except signing.BadSignature:
            raise SuspiciousOperation("Bad legacy data asset token signature")
        except ArtifactVersion.DoesNotExist:
            raise Http404
        if self._redirect_to_files:
            return HttpResponseRedirect(default_storage.url(data_asset.file.name))
        else:
            return FileResponse(default_storage.open(data_asset.file.name),
                                as_attachment=True, content_type=data_asset.get_content_type())


class ProfileDownloadView(View):
    def get(self, response, *args, **kwargs):
        # TODO DownloadProfileEvent with mdm namespace
        try:
            profile, enrollment_session, enrolled_user = load_legacy_profile_token(kwargs["token"])
        except signing.BadSignature:
            raise SuspiciousOperation("Bad legacy profile token signature")
        except ArtifactVersion.DoesNotExist:
            raise Http404
        return HttpResponse(build_payload(profile, enrollment_session, enrolled_user),
                            content_type="application/x-apple-aspen-config")
