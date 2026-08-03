from unittest.mock import patch
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.compliance_checks import TurboScript
from zentral.contrib.turbo.models import Script
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import (TurboAPITestCase, force_configuration, force_one_time_job,
                    force_recurring_job, force_script)


class TurboScriptAPITestCase(TurboAPITestCase):
    def test_create_script_plain(self):
        self.set_permissions("turbo.add_script")
        name = get_random_string(12)
        response = self.post(reverse("turbo_api:scripts"),
                             {"name": name, "source": "echo ok"})
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["version"], 1)
        self.assertIsNone(data["compliance_check_id"])
        self.assertFalse(data["compliance_check_enabled"])
        script = Script.objects.get(pk=data["id"])
        self.assertEqual(script.job.kind, "script")
        self.assertEqual(data["job_id"], str(script.job_id))
        self.assertIsNone(script.compliance_check)

    def test_create_script_compliance(self):
        self.set_permissions("turbo.add_script")
        name = get_random_string(12)
        response = self.post(reverse("turbo_api:scripts"),
                             {"name": name, "source": "echo ok", "compliance_check_enabled": True})
        self.assertEqual(response.status_code, 201)
        data = response.json()
        script = Script.objects.get(pk=data["id"])
        self.assertIsNotNone(script.compliance_check)
        self.assertEqual(data["compliance_check_id"], script.compliance_check.pk)
        self.assertTrue(data["compliance_check_enabled"])
        self.assertEqual(script.compliance_check.model, TurboScript.get_model())
        self.assertEqual(script.compliance_check.name, name)
        self.assertEqual(script.compliance_check.version, script.job.version)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_script_compliance_and_tag_are_combinable(self, post_event):
        # unlike osquery, a turbo script can be both a compliance check and a tagging script
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("turbo.add_script")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:scripts"),
                                 {"name": get_random_string(12), "source": "echo ok",
                                  "compliance_check_enabled": True, "tag": tag.pk})
        self.assertEqual(response.status_code, 201)
        script = Script.objects.get(pk=response.json()["id"])
        self.assertIsNotNone(script.compliance_check)
        self.assertEqual(script.tag, tag)
        # the audit event links the script + the tagging tag, deliberately NOT the compliance check
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.script")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(metadata["objects"], {
            "turbo_script": [str(script.pk)],
            "tag": [str(tag.pk)],
        })

    def test_list_scripts(self):
        # ordered by name — LimitOffset pagination over an unordered queryset returns unstable pages.
        # lowercase prefixes so the expected order does not depend on the database collation
        scripts = [force_script(name=f"{p}{get_random_string(8)}") for p in ("a", "b")]
        self.set_permissions("turbo.view_script")
        response = self.get(reverse("turbo_api:scripts"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)
        self.assertEqual([s["id"] for s in response.json()["results"]],
                         [str(s.pk) for s in scripts])

    def test_list_scripts_constant_query_count(self):
        # compliance_check_enabled reads the FK id, not the related object → no per-row N+1
        self.set_permissions("turbo.view_script")
        force_script(compliance_check=True)
        self.get(reverse("turbo_api:scripts"))  # warm process-level caches
        with CaptureQueriesContext(connection) as one:
            self.assertEqual(self.get(reverse("turbo_api:scripts")).status_code, 200)
        for _ in range(4):
            force_script(compliance_check=True)
        with CaptureQueriesContext(connection) as five:
            self.assertEqual(self.get(reverse("turbo_api:scripts")).status_code, 200)
        self.assertEqual(len(one.captured_queries), len(five.captured_queries))

    def test_list_scripts_filter_by_configuration(self):
        # a script's configuration is reached through its Job's schedules — both the recurring and the
        # one-time path count; an unscheduled script is excluded
        configuration = force_configuration()
        recurring_script = force_script()
        force_recurring_job(configuration=configuration, job=recurring_script.job)
        one_time_script = force_script()
        force_one_time_job(configuration=configuration, job=one_time_script.job)
        force_script()  # unscheduled
        self.set_permissions("turbo.view_script")
        response = self.get(reverse("turbo_api:scripts"), {"configuration": str(configuration.pk)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual({r["id"] for r in response.json()["results"]},
                         {str(recurring_script.pk), str(one_time_script.pk)})

    def test_create_script_no_architecture(self):
        # a script that runs on neither architecture would silently never run — rejected like the UI
        self.set_permissions("turbo.add_script")
        response = self.post(reverse("turbo_api:scripts"),
                             {"name": get_random_string(12), "source": "echo ok",
                              "arch_amd64": False, "arch_arm64": False})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Script.objects.count(), 0)

    def test_update_script_source_bumps_version(self):
        script = force_script(compliance_check=True)
        cc_pk = script.compliance_check.pk
        version = script.job.version
        self.set_permissions("turbo.change_script")
        response = self.put(reverse("turbo_api:script", args=(script.pk,)),
                            {"name": script.name, "source": "echo changed", "compliance_check_enabled": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["version"], version + 1)
        script = Script.objects.get(pk=script.pk)
        self.assertEqual(script.job.version, version + 1)
        self.assertEqual(script.compliance_check.pk, cc_pk)
        self.assertEqual(script.compliance_check.version, script.job.version)

    def test_update_script_disable_compliance(self):
        script = force_script(compliance_check=True)
        cc_pk = script.compliance_check.pk
        self.set_permissions("turbo.change_script")
        response = self.put(reverse("turbo_api:script", args=(script.pk,)),
                            {"name": script.name, "source": script.source, "compliance_check_enabled": False})
        self.assertEqual(response.status_code, 200)
        # the response must reflect the disabled state, not the deleted check (SET_NULL leaves the
        # in-memory instance stale unless the sync refreshes it)
        self.assertIsNone(response.data["compliance_check_id"])
        self.assertFalse(response.data["compliance_check_enabled"])
        script = Script.objects.get(pk=script.pk)
        self.assertIsNone(script.compliance_check)
        self.assertFalse(ComplianceCheck.objects.filter(pk=cc_pk).exists())

    def test_patch_script_method_not_allowed(self):
        # Zentral only does full updates — PATCH is rejected by the shared audit view, so
        # ScriptSerializer.update() can rely on compliance_check_enabled being present
        script = force_script()
        self.set_permissions("turbo.change_script")
        response = self.client.patch(reverse("turbo_api:script", args=(script.pk,)),
                                     data={"description": "partial"},
                                     content_type="application/json",
                                     HTTP_AUTHORIZATION=f"Token {self._get_api_key()}")
        self.assertEqual(response.status_code, 405)

    def test_delete_script_deletes_compliance_check(self):
        script = force_script(compliance_check=True)
        cc_pk = script.compliance_check.pk
        self.set_permissions("turbo.delete_script")
        response = self.delete(reverse("turbo_api:script", args=(script.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Script.objects.filter(pk=script.pk).exists())
        self.assertFalse(ComplianceCheck.objects.filter(pk=cc_pk).exists())

    def test_delete_scheduled_script_blocked(self):
        script = force_script()
        force_recurring_job(job=script.job)
        self.set_permissions("turbo.delete_script")
        response = self.delete(reverse("turbo_api:script", args=(script.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertTrue(Script.objects.filter(pk=script.pk).exists())
