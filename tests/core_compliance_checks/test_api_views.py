from datetime import timedelta
from urllib.parse import urlencode
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.core.compliance_checks.models import ComplianceCheck, MachineStatus, Status
from zentral.utils.time import naive_utcnow


class ComplianceChecksAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.service_account

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "compliance_checks_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utility methods

    def _force_compliance_check(self, model=None, version=1):
        return ComplianceCheck.objects.create(
            model=model or get_random_string(12),
            name=get_random_string(12),
            description=get_random_string(12),
            version=version,
        )

    def _force_machine_status(self, compliance_check, status, version=None, previous_status=None, serial_number=None):
        return MachineStatus.objects.create(
            compliance_check=compliance_check,
            compliance_check_version=version or compliance_check.version,
            serial_number=serial_number or get_random_string(12),
            status=status.value,
            status_time=naive_utcnow() - timedelta(hours=1),
            previous_status=previous_status.value if previous_status else None,
        )

    def _status_counts(self, **counts):
        return {"OK": 0, "PENDING": 0, "UNKNOWN": 0, "FAILED": 0, "OUT_OF_SCOPE": 0, **counts}

    def _serialized_compliance_check(self, compliance_check, outdated_count=0, **counts):
        return {
            "id": compliance_check.pk,
            "model": compliance_check.model,
            "name": compliance_check.name,
            "description": compliance_check.description,
            "version": compliance_check.version,
            "status_counts": self._status_counts(**counts),
            "outdated_count": outdated_count,
            "created_at": compliance_check.created_at.isoformat(),
            "updated_at": compliance_check.updated_at.isoformat(),
        }

    def _serialized_machine_status(self, machine_status):
        return {
            "id": machine_status.pk,
            "compliance_check": machine_status.compliance_check.pk,
            "compliance_check_version": machine_status.compliance_check_version,
            "serial_number": machine_status.serial_number,
            "status": Status(machine_status.status).name,
            "status_time": machine_status.status_time.isoformat(),
            "previous_status": (
                Status(machine_status.previous_status).name if machine_status.previous_status is not None else None
            ),
        }

    # list compliance checks

    def test_list_compliance_checks_unauthorized(self):
        response = self.get(reverse("compliance_checks_api:compliance_checks"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_compliance_checks_permission_denied(self):
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:compliance_checks"))
        self.assertEqual(response.status_code, 403)

    def test_list_compliance_checks_empty(self):
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"count": 0, "next": None, "previous": None, "results": []})

    def test_list_compliance_checks(self):
        cc1 = self._force_compliance_check(version=2)
        self._force_machine_status(cc1, Status.OK)
        self._force_machine_status(cc1, Status.OK, previous_status=Status.FAILED)
        self._force_machine_status(cc1, Status.FAILED)
        # recorded for an older version of the check
        self._force_machine_status(cc1, Status.FAILED, version=1)
        self._force_machine_status(cc1, Status.PENDING)
        self._force_machine_status(cc1, Status.OUT_OF_SCOPE)
        cc2 = self._force_compliance_check()
        self._force_machine_status(cc2, Status.UNKNOWN)
        cc3 = self._force_compliance_check()
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 3,
             "next": None,
             "previous": None,
             "results": [
                 self._serialized_compliance_check(cc1, outdated_count=1, OK=2, PENDING=1, FAILED=1, OUT_OF_SCOPE=1),
                 self._serialized_compliance_check(cc2, UNKNOWN=1),
                 self._serialized_compliance_check(cc3),
             ]}
        )

    def test_list_compliance_checks_pagination(self):
        cc1 = self._force_compliance_check()
        self._force_machine_status(cc1, Status.OK)
        cc2 = self._force_compliance_check()
        self._force_machine_status(cc2, Status.FAILED)
        cc3 = self._force_compliance_check()
        self._force_machine_status(cc3, Status.UNKNOWN)
        self.set_permissions("compliance_checks.view_compliancecheck")
        url = reverse("compliance_checks_api:compliance_checks")
        response = self.get(f"{url}?{urlencode({'limit': 2, 'offset': 1})}")
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        self.assertEqual(response_json["count"], 3)
        self.assertIsNone(response_json["next"])
        self.assertTrue(response_json["previous"].endswith(f"{url}?limit=2"))
        self.assertEqual(
            response_json["results"],
            [self._serialized_compliance_check(cc2, FAILED=1),
             self._serialized_compliance_check(cc3, UNKNOWN=1)]
        )

    def test_list_compliance_checks_query_count_independent_of_page_size(self):
        for status in (Status.OK, Status.FAILED, Status.UNKNOWN):
            self._force_machine_status(self._force_compliance_check(), status)
        self.set_permissions("compliance_checks.view_compliancecheck")
        url = reverse("compliance_checks_api:compliance_checks")
        # warm up, the first request can load and cache the policies
        self.assertEqual(self.get(url).status_code, 200)
        query_counts = []
        for limit in (1, 3):
            with CaptureQueriesContext(connection) as ctx:
                response = self.get(f"{url}?{urlencode({'limit': limit})}")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()["results"]), limit)
            query_counts.append(len(ctx.captured_queries))
        self.assertEqual(query_counts[0], query_counts[1])

    def test_list_compliance_checks_filter_by_model(self):
        cc1 = self._force_compliance_check()
        self._force_compliance_check()
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_checks"), data={"model": cc1.model})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 1, "next": None, "previous": None,
             "results": [self._serialized_compliance_check(cc1)]}
        )

    def test_list_compliance_checks_filter_by_name(self):
        self._force_compliance_check()
        cc2 = self._force_compliance_check()
        self._force_machine_status(cc2, Status.OK)
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_checks"), data={"name": cc2.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 1, "next": None, "previous": None,
             "results": [self._serialized_compliance_check(cc2, OK=1)]}
        )

    # get compliance check

    def test_get_compliance_check_unauthorized(self):
        cc = self._force_compliance_check()
        response = self.get(reverse("compliance_checks_api:compliance_check", args=(cc.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_compliance_check_permission_denied(self):
        cc = self._force_compliance_check()
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_compliance_check_not_found(self):
        cc = self._force_compliance_check()
        cc_pk = cc.pk
        cc.delete()
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_check", args=(cc_pk,)))
        self.assertEqual(response.status_code, 404)

    def test_get_compliance_check(self):
        cc = self._force_compliance_check(version=3)
        self._force_machine_status(cc, Status.OK)
        self._force_machine_status(cc, Status.FAILED, version=2)
        self._force_machine_status(cc, Status.OK, version=1)
        self._force_machine_status(cc, Status.FAILED)
        self._force_machine_status(cc, Status.UNKNOWN)
        self._force_machine_status(self._force_compliance_check(), Status.OK)
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._serialized_compliance_check(cc, outdated_count=2, OK=1, FAILED=1, UNKNOWN=1)
        )

    # list machine statuses

    def test_list_machine_statuses_unauthorized(self):
        response = self.get(reverse("compliance_checks_api:machine_statuses"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_machine_statuses_permission_denied(self):
        self.set_permissions("compliance_checks.view_compliancecheck")
        response = self.get(reverse("compliance_checks_api:machine_statuses"))
        self.assertEqual(response.status_code, 403)

    def test_list_machine_statuses(self):
        cc1 = self._force_compliance_check(version=2)
        ms1 = self._force_machine_status(cc1, Status.FAILED, previous_status=Status.OK)
        ms2 = self._force_machine_status(cc1, Status.OK, version=1)
        cc2 = self._force_compliance_check()
        ms3 = self._force_machine_status(cc2, Status.OUT_OF_SCOPE, previous_status=Status.PENDING)
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:machine_statuses"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 3,
             "next": None,
             "previous": None,
             "results": [self._serialized_machine_status(ms) for ms in (ms1, ms2, ms3)]}
        )
        results = response.json()["results"]
        self.assertEqual(
            [(r["status"], r["previous_status"], r["compliance_check_version"]) for r in results],
            [("FAILED", "OK", 2), ("OK", None, 1), ("OUT_OF_SCOPE", "PENDING", 1)]
        )

    def test_list_machine_statuses_pagination(self):
        cc = self._force_compliance_check()
        machine_statuses = [self._force_machine_status(cc, Status.OK) for _ in range(3)]
        self.set_permissions("compliance_checks.view_machinestatus")
        url = reverse("compliance_checks_api:machine_statuses")
        seen = []
        next_url = f"{url}?{urlencode({'limit': 2})}"
        while next_url:
            response = self.get(next_url)
            self.assertEqual(response.status_code, 200)
            page = response.json()
            self.assertEqual(page["count"], 3)
            seen.extend(r["id"] for r in page["results"])
            next_url = page["next"]
        self.assertEqual(seen, [ms.pk for ms in machine_statuses])

    def test_list_machine_statuses_filter_by_serial_number(self):
        serial_number = get_random_string(12)
        cc1 = self._force_compliance_check()
        ms1 = self._force_machine_status(cc1, Status.OK, serial_number=serial_number)
        self._force_machine_status(cc1, Status.OK)
        cc2 = self._force_compliance_check()
        ms2 = self._force_machine_status(cc2, Status.FAILED, serial_number=serial_number)
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:machine_statuses"), data={"serial_number": serial_number})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 2, "next": None, "previous": None,
             "results": [self._serialized_machine_status(ms1), self._serialized_machine_status(ms2)]}
        )

    def test_list_machine_statuses_filter_by_compliance_check(self):
        serial_number = get_random_string(12)
        cc1 = self._force_compliance_check()
        ms1 = self._force_machine_status(cc1, Status.OK, serial_number=serial_number)
        ms2 = self._force_machine_status(cc1, Status.UNKNOWN)
        cc2 = self._force_compliance_check()
        self._force_machine_status(cc2, Status.FAILED, serial_number=serial_number)
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:machine_statuses"), data={"compliance_check_id": cc1.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 2, "next": None, "previous": None,
             "results": [self._serialized_machine_status(ms1), self._serialized_machine_status(ms2)]}
        )

    def test_list_machine_statuses_filter_by_serial_number_and_compliance_check(self):
        serial_number = get_random_string(12)
        cc1 = self._force_compliance_check()
        ms = self._force_machine_status(cc1, Status.OK, serial_number=serial_number)
        self._force_machine_status(cc1, Status.UNKNOWN)
        cc2 = self._force_compliance_check()
        self._force_machine_status(cc2, Status.FAILED, serial_number=serial_number)
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:machine_statuses"),
                            data={"serial_number": serial_number, "compliance_check_id": cc1.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"count": 1, "next": None, "previous": None,
             "results": [self._serialized_machine_status(ms)]}
        )

    def test_list_machine_statuses_filter_by_unknown_compliance_check(self):
        cc = self._force_compliance_check()
        self._force_machine_status(cc, Status.OK)
        cc_pk = cc.pk
        cc.delete()
        self.set_permissions("compliance_checks.view_machinestatus")
        response = self.get(reverse("compliance_checks_api:machine_statuses"), data={"compliance_check_id": cc_pk})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {"compliance_check_id": ["Select a valid choice. That choice is not one of the available choices."]}
        )
