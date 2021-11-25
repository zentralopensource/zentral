import json
import logging
from uuid import UUID
import zlib
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import JsonResponse
from django.views.generic import View
from zentral.contrib.inventory.conf import macos_version_from_build
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MachineTag, MetaMachine, PrincipalUserSource
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events, verify_enrollment_secret
from zentral.contrib.santa.events import post_enrollment_event, process_events, post_preflight_event
from zentral.contrib.santa.models import Configuration, EnrolledMachine, Enrollment, MachineRule
from zentral.utils.certificates import parse_dn
from zentral.utils.http import user_agent_and_ip_address_from_request


logger = logging.getLogger('zentral.contrib.santa.views.api')


class BaseSyncView(View):
    use_enrolled_machine_cache = True

    def _get_client_cert_dn(self):
        dn = self.request.META.get("HTTP_X_SSL_CLIENT_S_DN")
        if dn:
            return parse_dn(dn)
        else:
            return None

    def _get_json_data(self, request):
        payload = request.body
        if not payload:
            return None
        try:
            if request.META.get('HTTP_CONTENT_ENCODING', None) in ("zlib", "deflate"):
                payload = zlib.decompress(payload)
            return json.loads(payload)
        except ValueError:
            raise SuspiciousOperation("Could not read JSON data")

    def get_enrolled_machine(self):
        try:
            enrolled_machine = EnrolledMachine.objects.select_related(
                "enrollment__secret",
                "enrollment__configuration"
            ).get(
                enrollment__secret__secret=self.enrollment_secret_secret,
                hardware_uuid=self.hardware_uuid
            )
        except EnrolledMachine.DoesNotExist:
            pass
        else:
            if enrolled_machine.enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
                raise PermissionDenied("Missing client certificate")
            return enrolled_machine

    def post(self, request, *args, **kwargs):
        # URL kwargs
        self.enrollment_secret_secret = kwargs["enrollment_secret"]
        try:
            self.hardware_uuid = str(UUID(kwargs["machine_id"]))
        except ValueError:
            raise PermissionDenied("Invalid machine id")

        self.client_cert_dn = self._get_client_cert_dn()

        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)

        self.request_data = self._get_json_data(request)

        self.cache_key = f"tests/santa/fixtures/{self.enrollment_secret_secret}{self.hardware_uuid}"
        self.enrolled_machine = None
        self.tag_ids = []
        if self.use_enrolled_machine_cache:
            try:
                self.enrolled_machine, self.tag_ids = cache.get(self.cache_key)
            except TypeError:
                pass
            else:
                if self.enrolled_machine.enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
                    raise PermissionDenied("Missing client certificate")
        if not self.enrolled_machine:
            self.enrolled_machine = self.get_enrolled_machine()
            if not self.enrolled_machine:
                raise PermissionDenied("Machine not enrolled")
            meta_machine = MetaMachine(self.enrolled_machine.serial_number)
            self.tag_ids = [t.id for t in meta_machine.tags]
            cache.set(self.cache_key, (self.enrolled_machine, self.tag_ids), 600)  # TODO cache timeout hardcoded

        return JsonResponse(self.do_post())


class PreflightView(BaseSyncView):
    use_enrolled_machine_cache = False

    def _get_primary_user(self):
        # primary user
        primary_user = self.request_data.get('primary_user')
        if primary_user:
            primary_user = primary_user.strip()
            if primary_user:
                return primary_user
        return None

    def _get_enrolled_machine_defaults(self):
        defaults = {
            'serial_number': self.request_data['serial_num'],
            'primary_user': self._get_primary_user(),
            'client_mode': Configuration.MONITOR_MODE,
            'santa_version': self.request_data['santa_version'],
            'binary_rule_count': self.request_data.get('binary_rule_count'),
            'certificate_rule_count': self.request_data.get('certificate_rule_count'),
            'compiler_rule_count': self.request_data.get('compiler_rule_count'),
            'transitive_rule_count': self.request_data.get('transitive_rule_count'),
        }
        # client mode
        req_client_mode = self.request_data.get('client_mode')
        if req_client_mode == "LOCKDOWN":
            defaults['client_mode'] = Configuration.LOCKDOWN_MODE
        elif req_client_mode != "MONITOR":
            logger.error(f"Unknown client mode: {req_client_mode}")
        return defaults

    def _enroll_machine(self):
        try:
            enrollment = (Enrollment.objects.select_related("configuration", "secret")
                                    .get(secret__secret=self.enrollment_secret_secret))
        except Enrollment.DoesNotExist:
            raise PermissionDenied("Unknown enrollment secret")
        if enrollment.configuration.client_certificate_auth and not self.client_cert_dn:
            raise PermissionDenied("Missing client certificate")
        try:
            verify_enrollment_secret(
                "santa_enrollment", self.enrollment_secret_secret,
                self.user_agent, self.ip,
                serial_number=self.request_data["serial_num"],
                udid=self.hardware_uuid,
            )
        except EnrollmentSecretVerificationFailed:
            raise PermissionDenied("Wrong enrollment secret")

        # get or create enrolled machine
        enrolled_machine, _ = EnrolledMachine.objects.update_or_create(
            enrollment=enrollment,
            hardware_uuid=self.hardware_uuid,
            defaults=self._get_enrolled_machine_defaults(),
        )

        # apply enrollment secret tags
        for tag in enrollment.secret.tags.all():
            MachineTag.objects.get_or_create(serial_number=enrolled_machine.serial_number, tag=tag)

        # delete other enrolled machines
        other_enrolled_machines = (EnrolledMachine.objects.exclude(pk=enrolled_machine.pk)
                                                          .filter(hardware_uuid=self.hardware_uuid))
        if other_enrolled_machines.count():
            self.enrollment_action = 're-enrollment'
            other_enrolled_machines.delete()
        else:
            self.enrollment_action = 'enrollment'

        # post event
        post_enrollment_event(
            enrolled_machine.serial_number, self.user_agent, self.ip,
            {'configuration': enrollment.configuration.serialize_for_event(),
             'action': self.enrollment_action}
        )

        return enrolled_machine

    def get_enrolled_machine(self):
        self.enrollment_action = None
        enrolled_machine = super().get_enrolled_machine()
        if not enrolled_machine:
            enrolled_machine = self._enroll_machine()
        else:
            enrolled_machine_changed = False
            for attr, val in self._get_enrolled_machine_defaults().items():
                if getattr(enrolled_machine, attr) != val:
                    setattr(enrolled_machine, attr, val)
                    enrolled_machine_changed = True
            if enrolled_machine_changed:
                enrolled_machine.save()
        return enrolled_machine

    def _commit_machine_snapshot(self):
        # os version
        build = self.request_data["os_build"]
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in self.request_data['os_version'].split('.'))))
        os_version.update({'name': 'macOS', 'build': build})
        try:
            os_version.update(macos_version_from_build(build))
        except ValueError:
            pass

        # tree
        tree = {'source': {'module': 'zentral.contrib.santa',
                           'name': 'Santa'},
                'reference': self.hardware_uuid,
                'serial_number': self.enrolled_machine.serial_number,
                'os_version': os_version,
                'system_info': {'computer_name': self.request_data['hostname']},
                'public_ip_address': self.ip,
                }

        # tree primary user
        primary_user = self._get_primary_user()
        if primary_user:
            tree['principal_user'] = {
                'source': {'type': PrincipalUserSource.SANTA_MACHINE_OWNER},
                'unique_id': primary_user,
                'principal_name': primary_user,
            }

        # tree business unit
        business_unit = self.enrolled_machine.enrollment.secret.get_api_enrollment_business_unit()
        if business_unit:
            tree['business_unit'] = business_unit.serialize()

        commit_machine_snapshot_and_trigger_events(tree)

    def do_post(self):
        post_preflight_event(self.enrolled_machine.serial_number,
                             self.user_agent,
                             self.ip,
                             self.request_data)

        self._commit_machine_snapshot()

        response_dict = self.enrolled_machine.enrollment.configuration.get_sync_server_config(
            self.enrolled_machine.santa_version
        )

        # clean sync?
        if self.request_data.get("request_clean_sync") is True or self.enrollment_action is not None:
            MachineRule.objects.filter(enrolled_machine=self.enrolled_machine).delete()
            response_dict["clean_sync"] = True

        return response_dict


class RuleDownloadView(BaseSyncView):
    def do_post(self):
        request_cursor = self.request_data.get("cursor")
        rules, response_cursor = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, self.tag_ids, request_cursor
        )
        response_dict = {"rules": rules}
        if response_cursor:
            # If a cursor is present in response, santa will make an extra request.
            # This is used to acknowlege the rules. There will be always one extra query to validate the last batch.
            # This is more robust than keeping the cursor on the enrolled machine and updating the cache to pass it
            # to the Postflight view to validate the last batch.
            response_dict["cursor"] = response_cursor
        return response_dict


class EventUploadView(BaseSyncView):
    def do_post(self):
        unknown_file_bundle_hashes = process_events(
            self.enrolled_machine,
            self.user_agent,
            self.ip,
            self.request_data
        )
        response_dict = {}
        if unknown_file_bundle_hashes:
            response_dict["event_upload_bundle_binaries"] = unknown_file_bundle_hashes
        return response_dict


class PostflightView(BaseSyncView):
    def do_post(self):
        cache.delete(self.cache_key)
        return {}
