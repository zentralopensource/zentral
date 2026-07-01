import hashlib
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.turbo.compliance_checks import sync_script_compliance_check
from zentral.contrib.turbo.models import (Configuration, EnrolledMachine, Enrollment, MSCPCheck,
                                          OneTimeJob, RecurringJob, Script)
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


def force_configuration():
    return Configuration.objects.create(name=get_random_string(12))


def force_script(compliance_check=False, tag=None, source="echo ok"):
    # the Job (kind=script) is auto-minted in Script.save()
    script = Script.objects.create(name=get_random_string(12), source=source, tag=tag)
    sync_script_compliance_check(script, compliance_check)
    return script


def force_mscp_check(rule_id=None, baseline="", odv_int=None, odv_string=None, odv_bool=None):
    # the Job (kind=mscp_check) and the compliance check are auto-minted in MSCPCheck.save()
    return MSCPCheck.objects.create(
        rule_id=rule_id or get_random_string(12),
        baseline=baseline,
        odv_int=odv_int,
        odv_string=odv_string,
        odv_bool=odv_bool,
    )


def force_recurring_job(configuration=None, job=None, interval=None, tags=None, serial_numbers=None):
    if configuration is None:
        configuration = force_configuration()
    if job is None:
        job = force_script().job
    recurring_job = RecurringJob.objects.create(
        configuration=configuration, job=job, interval=interval,
        serial_numbers=serial_numbers or [],
    )
    if tags:
        recurring_job.tags.set(tags)
    return recurring_job


def force_one_time_job(configuration=None, job=None, not_before=None, not_after=None,
                       tags=None, serial_numbers=None):
    if configuration is None:
        configuration = force_configuration()
    if job is None:
        job = force_script().job
    one_time_job = OneTimeJob.objects.create(
        configuration=configuration, job=job, not_before=not_before, not_after=not_after,
        serial_numbers=serial_numbers or [],
    )
    if tags:
        one_time_job.tags.set(tags)
    return one_time_job


def force_enrollment(
    configuration=None,
    enrollment_secret=None,
    meta_business_unit=None,
    tags=None,
):
    if configuration is None:
        configuration = force_configuration()
    if enrollment_secret is None:
        if meta_business_unit is None:
            meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=meta_business_unit)
    if tags:
        enrollment_secret.tags.set(tags)
    return Enrollment.objects.create(
        configuration=configuration,
        secret=enrollment_secret,
    )


def make_enrolled_machine(enrollment):
    return EnrolledMachine.objects.create(
        enrollment=enrollment,
        serial_number=get_random_string(32),
        token_hash=get_random_string(64),
    )


def force_enrolled_machine(configuration=None, meta_business_unit=None, tags=None, serial_number=None):
    # returns (enrollment, serial_number, plaintext_token); token_hash = sha256(token) so the
    # TurboEnrolledMachine auth resolves it
    enrollment = force_enrollment(configuration=configuration, meta_business_unit=meta_business_unit, tags=tags)
    serial_number = serial_number or get_random_string(12)
    token = get_random_string(64)
    EnrolledMachine.objects.create(
        enrollment=enrollment, serial_number=serial_number,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
    )
    return enrollment, serial_number, token


class TurboSetupTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        provision()
        stores._load(force=True)
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "turbo"

    @staticmethod
    def _audit_events(post_event):
        return [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]


class TurboPublicTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        provision()
        stores._load(force=True)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()


class TurboAPITestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # LoginCase / RequestCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "turbo"

    def _get_api_key(self):
        return self.api_key

    @staticmethod
    def _audit_events(post_event):
        return [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]
