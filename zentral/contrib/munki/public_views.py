from datetime import datetime, timedelta
import json
import logging
from dateutil import parser
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse
from django.utils.crypto import get_random_string
from django.utils.timezone import is_aware, make_naive
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.utils import (add_machine_tags,
                                             commit_machine_snapshot_and_trigger_events,
                                             verify_enrollment_secret)
from zentral.core.events.base import post_machine_conflict_event
from zentral.utils.api_views import APIAuthError, JSONPostAPIView
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.json import remove_null_character
from zentral.utils.os_version import make_comparable_os_version
from .compliance_checks import (prune_out_of_scope_machine_statuses,
                                serialize_script_check_for_job,
                                update_machine_munki_script_check_statuses)
from .events import post_munki_enrollment_event, post_munki_events, post_munki_request_event
from .models import EnrolledMachine, ManagedInstall, MunkiState, ScriptCheck
from .utils import apply_managed_installs, prepare_ms_tree_certificates, update_managed_install_with_event


logger = logging.getLogger('zentral.contrib.munki.public_views')


class EnrollView(View):
    def post(self, request, *args, **kwargs):
        user_agent, ip = user_agent_and_ip_address_from_request(request)
        try:
            request_json = json.loads(request.body.decode("utf-8"))
            secret = request_json["secret"]
            serial_number = request_json["serial_number"]
            uuid = request_json["uuid"]
            es_request = verify_enrollment_secret(
                "munki_enrollment", secret,
                user_agent, ip,
                serial_number, uuid
            )
        except (KeyError, ValueError, EnrollmentSecretVerificationFailed):
            raise SuspiciousOperation
        else:
            # get or create enrolled machine
            enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
                enrollment=es_request.enrollment_secret.munki_enrollment,
                serial_number=serial_number,
                defaults={"token": get_random_string(64)}
            )

            # apply enrollment secret tags
            add_machine_tags(serial_number, es_request.enrollment_secret.tags.all(), request)

            # post event
            post_munki_enrollment_event(serial_number, user_agent, ip,
                                        {'action': "enrollment" if enrolled_machine_created else "re-enrollment"})
            return JsonResponse({"token": enrolled_machine.token})


class BaseView(JSONPostAPIView):
    def get_enrolled_machine_token(self, request):
        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if not authorization_header:
            raise APIAuthError("Missing or empty Authorization header")
        if "MunkiEnrolledMachine" not in authorization_header:
            raise APIAuthError("Wrong authorization token")
        return authorization_header.replace("MunkiEnrolledMachine", "").strip()

    def verify_enrolled_machine_token(self, token):
        cache_key = f"munki.{token}"
        try:
            self.enrollment, self.machine_serial_number, self.business_unit = cache.get(cache_key)
        except TypeError:
            try:
                enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__configuration",
                                                                           "enrollment__secret__meta_business_unit")
                                                           .get(token=token))
            except EnrolledMachine.DoesNotExist:
                raise APIAuthError("Enrolled machine does not exist")
            else:
                self.enrollment = enrolled_machine.enrollment
                self.machine_serial_number = enrolled_machine.serial_number
                self.business_unit = self.enrollment.secret.get_api_enrollment_business_unit()
            cache.set(cache_key, (self.enrollment, self.machine_serial_number, self.business_unit), timeout=600)

    def check_request_secret(self, request, *args, **kwargs):
        enrolled_machine_token = self.get_enrolled_machine_token(request)
        self.verify_enrolled_machine_token(enrolled_machine_token)


class JobDetailsView(BaseView):
    def check_data_secret(self, data):
        msn = data.get('machine_serial_number')
        if not msn:
            raise APIAuthError(
                f"No reported machine serial number. Request SN {self.machine_serial_number}."
            )
        if msn != self.machine_serial_number:
            # the serial number reported by the zentral postflight is not the one in the enrollment secret.
            auth_err = "Zentral postflight reported SN {} different from enrollment SN {}".format(
                msn, self.machine_serial_number
            )
            post_machine_conflict_event(self.request, "zentral.contrib.munki", msn, self.machine_serial_number, {})
            raise APIAuthError(auth_err)

    def do_post(self, data):
        post_munki_request_event(
            self.machine_serial_number,
            self.user_agent, self.ip,
            request_type="job_details",
            enrollment={"pk": self.enrollment.pk}
        )

        # serialize configuration
        configuration = self.enrollment.configuration
        response_d = {"apps_full_info_shard": configuration.inventory_apps_full_info_shard}
        if configuration.principal_user_detection_sources:
            principal_user_detection = response_d.setdefault("principal_user_detection", {})
            principal_user_detection["sources"] = configuration.principal_user_detection_sources
            if configuration.principal_user_detection_domains:
                principal_user_detection["domains"] = configuration.principal_user_detection_domains
        if configuration.collected_condition_keys:
            response_d["collected_condition_keys"] = configuration.collected_condition_keys

        # add tags
        # TODO better cache for the machine tags
        m = MetaMachine(self.machine_serial_number)
        response_d["incidents"] = [mi.incident.name for mi in m.open_incidents()]
        response_d["tags"] = [t[1] for t in m.tag_pks_and_names]

        munki_state = None
        now = datetime.utcnow()
        try:
            munki_state = MunkiState.objects.get(machine_serial_number=self.machine_serial_number)
        except MunkiState.DoesNotExist:
            pass

        # last seen sha1sum
        # last managed installs sync
        if munki_state:
            response_d['last_seen_sha1sum'] = munki_state.sha1sum
            response_d['managed_installs'] = (
                munki_state.force_full_sync_at is not None
                or munki_state.last_managed_installs_sync is None
                or (
                    now - munki_state.last_managed_installs_sync
                    > timedelta(days=configuration.managed_installs_sync_interval_days)
                )
            )

        # script checks
        os_version = data.get("os_version")
        arch = data.get("arch")
        if (
            os_version
            and arch
            and (
                munki_state is None
                or munki_state.force_full_sync_at is not None
                or munki_state.last_script_checks_run is None
                or (
                    now - munki_state.last_script_checks_run
                    > timedelta(seconds=configuration.script_checks_run_interval_seconds)
                )
            )
        ):
            data_err = False
            comparable_os_version = make_comparable_os_version(os_version)
            if comparable_os_version == (0, 0, 0):
                logger.error("Machine %s: could not build comparable OS version", m.serial_number)
                data_err = True
            arch_amd64 = arch_arm64 = False
            if arch == "arm64":
                arch_arm64 = True
            elif arch == "amd64":
                arch_amd64 = True
            else:
                data_err = True
                logger.error("Machine %s: unknown arch", m.serial_number)
            if not data_err:
                # add in scope script checks to response
                response_d['script_checks'] = []
                in_scope_cc_ids = []
                for script_check in ScriptCheck.objects.iter_in_scope(
                    comparable_os_version,
                    arch_amd64,
                    arch_arm64,
                    [t[0] for t in m.tag_pks_and_names]
                ):
                    in_scope_cc_ids.append(script_check.compliance_check.pk)
                    response_d['script_checks'].append(serialize_script_check_for_job(script_check))

                # delete machine status for compliance checks not in scope
                prune_out_of_scope_machine_statuses(self.machine_serial_number, in_scope_cc_ids)

        return response_d


class PostJobView(BaseView):
    def do_post(self, data):
        request_time = datetime.utcnow()

        # lock enrolled machine
        EnrolledMachine.objects.select_for_update().filter(serial_number=self.machine_serial_number)

        # commit machine snapshot
        ms_tree = data['machine_snapshot']
        ms_tree['source'] = {'module': 'zentral.contrib.munki',
                             'name': 'Munki'}
        ms_tree['reference'] = ms_tree['serial_number']
        ms_tree['public_ip_address'] = self.ip
        if self.business_unit:
            ms_tree['business_unit'] = self.business_unit.serialize()
        prepare_ms_tree_certificates(ms_tree)
        extra_facts = ms_tree.pop("extra_facts", None)
        if isinstance(extra_facts, dict):
            ms_tree["extra_facts"] = remove_null_character(extra_facts)
        # cleanup profiles
        reported_profiles = ms_tree.pop("profiles", None)
        if reported_profiles:
            profiles = []
            for profile in reported_profiles:
                if profile not in profiles:
                    profiles.append(profile)
                else:
                    logger.error("Duplicated profile %s for machine %s.",
                                 profile.get("uuid", "UNKNOWN UUID"), self.machine_serial_number)
            ms_tree["profiles"] = profiles
        # cleanup OS version
        if "os_version" in ms_tree:
            if ms_tree["os_version"].get("patch") is None:
                ms_tree["os_version"]["patch"] = 0
        ms = commit_machine_snapshot_and_trigger_events(ms_tree)
        if not ms:
            raise RuntimeError(f"Could not commit machine {self.machine_serial_number} snapshot")

        # delete all managed installs if last seen report not found
        # which is a good indicator that the machine has been wiped
        last_seen_report_found = data.get("last_seen_report_found")
        if last_seen_report_found is not None and not last_seen_report_found:
            ManagedInstall.objects.filter(machine_serial_number=self.machine_serial_number).delete()

        # prepare reports
        reports = []
        report_count = event_count = 0
        for r in data.pop('reports'):
            report_count += 1
            event_count += len(r.get("events", []))
            reports.append((
                parser.parse(r.pop('start_time')),
                parser.parse(r.pop('end_time')),
                r
            ))
        reports.sort()

        munki_request_event_kwargs = {
            "request_type": "postflight",
            "enrollment": {"pk": self.enrollment.pk},
            "report_count": report_count,
            "event_count": event_count,
        }
        if last_seen_report_found is not None:
            munki_request_event_kwargs["last_seen_report_found"] = last_seen_report_found

        # update machine managed installs
        managed_installs = data.get("managed_installs")
        if managed_installs is not None:
            munki_request_event_kwargs["managed_installs"] = True
            munki_request_event_kwargs["managed_install_count"] = len(managed_installs)
            # update managed installs using the complete list
            incident_updates = apply_managed_installs(
                self.machine_serial_number, managed_installs,
                self.enrollment.configuration
            )
            # incident updates are attached to the munki request event
            if incident_updates:
                munki_request_event_kwargs["incident_updates"] = incident_updates
        else:
            munki_request_event_kwargs["managed_installs"] = False
            # update managed installs using the install and removal events in the reports
            for _, _, report in reports:
                for created_at, event in report.get("events", []):
                    # time
                    event_time = parser.parse(created_at)
                    if is_aware(event_time):
                        event_time = make_naive(event_time)
                    for incident_update in update_managed_install_with_event(
                        self.machine_serial_number, event, event_time,
                        self.enrollment.configuration
                    ):
                        # incident updates are attached to each munki event
                        event.setdefault("incident_updates", []).append(incident_update)

        # script checks
        script_check_results = data.get("script_check_results")
        if script_check_results:
            munki_request_event_kwargs["script_check_results"] = True
            munki_request_event_kwargs["script_check_result_count"] = len(script_check_results)
            update_machine_munki_script_check_statuses(
                self.machine_serial_number,
                script_check_results,
                request_time
            )
        else:
            munki_request_event_kwargs["script_check_results"] = False

        # update machine munki state
        update_dict = {'user_agent': self.user_agent,
                       'ip': self.ip}
        if managed_installs is not None:
            update_dict["last_managed_installs_sync"] = request_time
        if script_check_results is not None:
            update_dict["last_script_checks_run"] = request_time
        if reports:
            start_time, end_time, report = reports[-1]
            update_dict.update({'munki_version': report.get('munki_version', None),
                                'sha1sum': report['sha1sum'],
                                'run_type': report['run_type'],
                                'start_time': start_time,
                                'end_time': end_time})
        if script_check_results is not None and managed_installs is not None:
            update_dict["force_full_sync_at"] = None
        MunkiState.objects.update_or_create(
            machine_serial_number=self.machine_serial_number,
            defaults=update_dict
        )

        # events
        post_munki_request_event(
            self.machine_serial_number,
            self.user_agent, self.ip,
            **munki_request_event_kwargs
        )

        post_munki_events(
            self.machine_serial_number,
            self.user_agent, self.ip,
            (r for _, _, r in reports)
        )

        return {}
