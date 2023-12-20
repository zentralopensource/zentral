from datetime import datetime
from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.core.compliance_checks.models import MachineStatus, Status
from zentral.contrib.inventory.models import Tag
from zentral.contrib.munki.compliance_checks import (convert_bool_expected_result,
                                                     serialize_script_check_for_job,
                                                     update_machine_munki_script_check_statuses,
                                                     validate_expected_result,
                                                     MunkiScriptCheck)
from zentral.contrib.munki.models import ScriptCheck
from .utils import force_script_check


class MunkiComplianceChecksTestCase(TestCase):

    # convert_bool_expected_result

    def test_convert_bool_expected_result_ok(self):
        for in_r, out_r in (("f", False),
                            ("F", False),
                            ("fAlSE", False),
                            ("t", True),
                            ("True", True),
                            ("0", False),
                            ("1", True)):
            self.assertEqual(convert_bool_expected_result(in_r), out_r)

    def test_convert_bool_expected_result_err(self):
        for in_r, exception in (("aaslkdja", ValueError),
                                ("100", AssertionError)):
            with self.assertRaises(exception):
                convert_bool_expected_result(in_r)

    # validate_expected_result

    def test_validate_expected_result(self):
        for sc_type, expected_result, ok, err in (
            ("ZSH_INT", "10", True, None),
            (ScriptCheck.Type.ZSH_INT, "1", True, None),
            ("ZSH_INT", "abc", False, "Invalid integer"),
            (ScriptCheck.Type.ZSH_INT, "abcdef", False, "Invalid integer"),
            ("ZSH_BOOL", "1", True, None),
            (ScriptCheck.Type.ZSH_BOOL, "10", False, "Invalid boolean"),
        ):
            self.assertEqual(validate_expected_result(sc_type, expected_result), (ok, err))

    # serialize_script_check_for_job

    def test_serialize_zsh_int_script_check_for_job(self):
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_INT,
            source="echo 10",
            expected_result="10",
        )
        self.assertEqual(
            serialize_script_check_for_job(sc),
            {"pk": sc.pk,
             "type": "ZSH_INT",
             "version": sc.compliance_check.version,
             "source": "echo 10",
             "expected_result": 10}
        )

    def test_serialize_zsh_bool_script_check_for_job(self):
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_BOOL,
            source="echo 1",
            expected_result="1",
        )
        self.assertEqual(
            serialize_script_check_for_job(sc),
            {"pk": sc.pk,
             "type": "ZSH_BOOL",
             "version": sc.compliance_check.version,
             "source": "echo 1",
             "expected_result": True}
        )

    def test_serialize_zsh_str_script_check_for_job(self):
        sc = force_script_check(
            type=ScriptCheck.Type.ZSH_STR,
            source="echo un",
            expected_result="un",
        )
        self.assertEqual(
            serialize_script_check_for_job(sc),
            {"pk": sc.pk,
             "type": "ZSH_STR",
             "version": sc.compliance_check.version,
             "source": "echo un",
             "expected_result": "un"}
        )

    # ScriptCheck

    def test_iter_in_scope_no_tags(self):
        sc = force_script_check()
        force_script_check(tags=[Tag.objects.create(name=get_random_string(12))])
        self.assertEqual(
            list(ScriptCheck.objects.iter_in_scope((14, 2, 1), False, True, [])),
            [sc]
        )

    def test_iter_in_scope_two_matching_tags(self):
        sc = force_script_check(excluded_tags=[Tag.objects.create(name=get_random_string(12))])
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        sc2 = force_script_check(tags=tags[:-1])
        self.assertEqual(
            sorted(ScriptCheck.objects.iter_in_scope((14, 2, 1), False, True, [t.pk for t in tags]),
                   key=lambda sc: sc.pk),
            [sc, sc2]
        )

    def test_iter_in_scope_one_matching_tag_two_matching_excluded_tags(self):
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        sc = force_script_check(tags=tags[1:], excluded_tags=[Tag.objects.create(name=get_random_string(12))])
        sc2 = force_script_check(tags=tags[2:])
        force_script_check(tags=tags[:-1], excluded_tags=tags[1:])
        self.assertEqual(
            sorted(ScriptCheck.objects.iter_in_scope((14, 2, 1), False, True, [t.pk for t in tags]),
                   key=lambda sc: sc.pk),
            [sc, sc2]
        )

    # MunkiScriptCheck

    def test_munki_script_check_script_check(self):
        sc = force_script_check()
        msc = MunkiScriptCheck(sc.compliance_check)
        self.assertEqual(msc.script_check, sc)

    def test_munki_script_check_script_check_does_not_exist(self):
        sc = force_script_check()
        msc = MunkiScriptCheck(sc.compliance_check)
        super(ScriptCheck, sc).delete()  # bypass the delete override
        sc.compliance_check.refresh_from_db()  # the compliance check still exists!
        self.assertIsNone(msc.script_check)

    def test_munki_script_check_get_redirect_url(self):
        sc = force_script_check()
        msc = MunkiScriptCheck(sc.compliance_check)
        self.assertEqual(msc.get_redirect_url(), sc.get_absolute_url())

    # update_machine_munki_script_check_statuses

    @patch("zentral.contrib.munki.compliance_checks.logger.error")
    def test_update_machine_munki_script_check_statuses_unknown_script_check(self, logger_error):
        update_machine_munki_script_check_statuses("123", [{"pk": 0}], datetime.utcnow())
        logger_error.assert_called_once_with("Machine %s: unknown script check %s in result", "123", 0)

    @patch("zentral.contrib.munki.compliance_checks.logger.error")
    def test_update_machine_munki_script_check_statuses_unknown_status(self, logger_error):
        sc = force_script_check()
        update_machine_munki_script_check_statuses("123", [{"pk": sc.pk, "status": "yolo"}], datetime.utcnow())
        logger_error.assert_called_once_with("Machine %s: unknown status value for script check %s in result",
                                             "123", sc.pk)

    @patch("zentral.contrib.munki.compliance_checks.logger.info")
    def test_update_machine_munki_script_check_statuses_outdated(self, logger_info):
        sc = force_script_check()
        sc.compliance_check.version = 2
        sc.compliance_check.save()
        update_machine_munki_script_check_statuses(
            "123", [{"pk": sc.pk, "status": Status.OK.value, "version": 1}], datetime.utcnow()
        )
        logger_info.assert_called_once_with("Machine %s: result for outdated script check %s", "123", sc.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_machine_munki_script_check_statuses_noop(self, post_event):
        sc = force_script_check()
        serial_number = get_random_string(12)
        ms = MachineStatus.objects.create(
            compliance_check=sc.compliance_check,
            compliance_check_version=sc.compliance_check.version,
            serial_number=serial_number,
            status=0,
            status_time=datetime(2000, 1, 1)
        )
        update_machine_munki_script_check_statuses(
            serial_number, [{"pk": sc.pk, "status": Status.OK.value, "version": 1}], datetime.utcnow()
        )
        ms_qs = MachineStatus.objects.filter(serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        self.assertEqual(ms_qs.first(), ms)
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_machine_munki_script_check_statuses_update(self, post_event):
        sc = force_script_check()
        serial_number = get_random_string(12)
        ms = MachineStatus.objects.create(
            compliance_check=sc.compliance_check,
            compliance_check_version=sc.compliance_check.version,
            serial_number=serial_number,
            status=Status.OK.value,
            status_time=datetime(2000, 1, 1)
        )
        status_time = datetime.utcnow()
        update_machine_munki_script_check_statuses(
            serial_number, [{"pk": sc.pk, "status": Status.FAILED.value, "version": 1}], status_time
        )
        ms_qs = MachineStatus.objects.filter(serial_number=serial_number)
        self.assertEqual(ms_qs.count(), 1)
        self.assertEqual(ms_qs.first(), ms)
        ms.refresh_from_db()
        self.assertEqual(ms.status, Status.FAILED.value)
        self.assertEqual(ms.status_time, status_time)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertEqual(
            event.payload,
            {"pk": sc.compliance_check.pk,
             "model": "MunkiScriptCheck",
             "name": sc.compliance_check.name,
             "description": "",
             "version": 1,
             "munki_script_check": {"pk": sc.pk},
             "status": "FAILED",
             "previous_status": "OK"}
        )
