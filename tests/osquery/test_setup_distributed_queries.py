from datetime import datetime
from functools import reduce
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.osquery.models import (DistributedQuery, DistributedQueryMachine, DistributedQueryResult,
                                            FileCarvingSession, Query)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupDistributedQueriesViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _force_distributed_query(self):
        query = self._force_query()
        return DistributedQuery.objects.create(
            query=query,
            query_version=query.version,
            sql=query.sql,
            valid_from=datetime.utcnow(),
        )

    def _force_query(self):
        return Query.objects.create(name=get_random_string(12), sql="select 1 from processes;")

    # create distributed query

    def test_create_distributed_query_redirect(self):
        query = self._force_query()
        self._login_redirect("{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk))

    def test_create_distributed_query_permission_denied(self):
        query = self._force_query()
        self._login()
        response = self.client.get("{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk))
        self.assertEqual(response.status_code, 403)

    def test_create_distributed_query_get(self):
        query = self._force_query()
        self._login("osquery.add_distributedquery")
        response = self.client.get("{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertContains(response, "Launch query")
        self.assertContains(response, query.name)
        self.assertNotContains(response, "Halt current")

    def test_create_distributed_query_post(self):
        query = self._force_query()
        self._login("osquery.add_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            "{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk),
            {"valid_from": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             "shard": "100"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_detail.html")
        self.assertEqual(response.context["query"], query)
        distributed_query = response.context["object"]
        self.assertEqual(distributed_query.query, query)
        self.assertEqual(distributed_query.sql, query.sql)
        self.assertEqual(distributed_query.query_version, query.version)

    def test_create_distributed_query_valid_until_less_than_valid_from(self):
        query = self._force_query()
        self._login("osquery.add_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            "{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk),
            {"valid_from": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             "valid_until": "2021-02-18 20:55:00",
             "shard": "100"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertContains(response, "Valid until must be greater than valid from")

    def test_create_distributed_query_valid_until_past(self):
        query = self._force_query()
        self._login("osquery.add_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            "{}?q={}".format(reverse("osquery:create_distributed_query"), query.pk),
            {"valid_from": "2020-07-30 11:50:00",
             "valid_until": "2021-02-18 20:55:00",
             "shard": "100"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertContains(response, "Valid until is in the past")

    def test_create_distributed_query_halt_current_get(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.add_distributedquery")
        response = self.client.post("{}?q={}".format(reverse("osquery:create_distributed_query"),
                                                     distributed_query.query.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertContains(response, "Launch query")
        self.assertContains(response, distributed_query.query.name)
        self.assertContains(response, "Halt current")

    def test_create_distributed_no_halt_current_post(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.add_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            "{}?q={}".format(reverse("osquery:create_distributed_query"), distributed_query.query.pk),
            {"valid_from": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             "shard": "100"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_detail.html")
        self.assertEqual(response.context["query"], distributed_query.query)
        distributed_query2 = response.context["object"]
        self.assertEqual(distributed_query.query, distributed_query2.query)
        distributed_query.refresh_from_db()
        self.assertEqual(distributed_query.valid_until, None)

    def test_create_distributed_halt_current_post(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.add_distributedquery", "osquery.view_distributedquery")
        pre_post_dt = datetime.utcnow()
        response = self.client.post(
            "{}?q={}".format(reverse("osquery:create_distributed_query"), distributed_query.query.pk),
            {"valid_from": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             "shard": "100",
             "halt_current_runs": "on"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_detail.html")
        self.assertEqual(response.context["query"], distributed_query.query)
        distributed_query2 = response.context["object"]
        self.assertEqual(distributed_query.query, distributed_query2.query)
        distributed_query.refresh_from_db()
        self.assertFalse(distributed_query.is_active())
        self.assertTrue(distributed_query.valid_until > pre_post_dt)
        self.assertTrue(distributed_query.valid_until < datetime.utcnow())

    # update distributed query

    def test_update_distributed_query_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:update_distributed_query", args=(distributed_query.pk,)))

    def test_update_distributed_query_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:update_distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_distributed_query_get(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.change_distributedquery")
        response = self.client.get(reverse("osquery:update_distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertEqual(response.context["object"], distributed_query)
        self.assertNotContains(response, "Halt current")

    def test_update_distributed_query_post(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.change_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            reverse("osquery:update_distributed_query", args=(distributed_query.pk,)),
            {"valid_from": "2020-07-30 11:50:00",
             "valid_until": "2021-02-18 20:55:00",
             "shard": "99"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_detail.html")
        self.assertEqual(response.context["object"], distributed_query)
        distributed_query.refresh_from_db()
        self.assertEqual(distributed_query.shard, 99)

    def test_update_distributed_query_valid_until_less_than_valid_from(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.change_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(
            reverse("osquery:update_distributed_query", args=(distributed_query.pk,)),
            {"valid_from": "2021-02-18 20:55:00",
             "valid_until": "2020-07-30 11:50:00",
             "shard": "99"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_form.html")
        self.assertEqual(response.context["object"], distributed_query)
        self.assertContains(response, "Valid until must be greater than valid from")

    # distributed query list

    def test_distributed_queries_redirect(self):
        self._login_redirect(reverse("osquery:distributed_queries"))

    def test_distributed_queries_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:distributed_queries"))
        self.assertEqual(response.status_code, 403)

    def test_distributed_queries_get(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.view_distributedquery")
        response = self.client.get(reverse("osquery:distributed_queries"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_list.html")
        self.assertNotContains(response, distributed_query.query.name)
        self._login("osquery.view_distributedquery", "osquery.view_query")
        response = self.client.get(reverse("osquery:distributed_queries"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_list.html")
        self.assertContains(response, distributed_query.query.name)

    # distributed query

    def test_distributed_query_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:distributed_query", args=(distributed_query.pk,)))

    def test_distributed_query_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_distributed_query(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.view_distributedquery")
        response = self.client.get(reverse("osquery:distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_detail.html")
        self.assertEqual(response.context["object"], distributed_query)

    # delete distributed query

    def test_delete_distributed_query_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:delete_distributed_query", args=(distributed_query.pk,)))

    def test_delete_distributed_query_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:delete_distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_distributed_query_get(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.delete_distributedquery")
        response = self.client.get(reverse("osquery:delete_distributed_query", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_confirm_delete.html")
        self.assertEqual(response.context["object"], distributed_query)

    def test_delete_distributed_query_post(self):
        distributed_query = self._force_distributed_query()
        self._login("osquery.delete_distributedquery", "osquery.view_distributedquery")
        response = self.client.post(reverse("osquery:delete_distributed_query", args=(distributed_query.pk,)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquery_list.html")
        self.assertNotIn(distributed_query, response.context["distributed_queries"])

    # distributed query machines

    def test_distributed_query_machines_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:distributed_query_machines", args=(distributed_query.pk,)))

    def test_distributed_query_machines_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:distributed_query_machines", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.osquery.views.distributed_queries.DistributedQueryMachineListView.get_paginate_by")
    def test_distributed_query_machines(self, get_paginate_by):
        get_paginate_by.return_value = 1
        distributed_query = self._force_distributed_query()
        dqm_count = 3
        serial_numbers = [get_random_string(12) for _ in range(dqm_count)]
        err_msgs = [get_random_string(12) for _ in range(dqm_count)]
        dqm_gen = (
            DistributedQueryMachine(
                distributed_query=distributed_query,
                serial_number=serial_numbers[i],
                status=3,
                error_message=err_msgs[i],
                memory=111111111111,
                system_time=222222222222,
                user_time=333333333333,
                wall_time_ms=444444444444,
            ) for i in range(dqm_count)
        )
        DistributedQueryMachine.objects.bulk_create(dqm_gen)
        self._login("osquery.view_distributedquery")
        response = self.client.get(reverse("osquery:distributed_query_machines", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquerymachine_list.html")
        self.assertContains(response, f"{dqm_count} Machines")
        self.assertContains(response, serial_numbers[-1])
        self.assertContains(response, "Error")
        self.assertContains(response, err_msgs[-1])
        self.assertContains(response, "111111111111")
        self.assertContains(response, "222222222222")
        self.assertContains(response, "333333333333")
        self.assertContains(response, "444444444444")

    # distributed query machines search

    def test_distributed_query_machines_serial_search(self):
        distributed_query = self._force_distributed_query()
        dqm_count = 3
        serial_numbers = [get_random_string(12) for _ in range(dqm_count)]
        serial_search = serial_numbers[0]
        dqm_gen = (
            DistributedQueryMachine(
                distributed_query=distributed_query,
                serial_number=serial_numbers[i],
                status=i,
                error_message=None,
            ) for i in range(dqm_count)
        )
        DistributedQueryMachine.objects.bulk_create(dqm_gen)
        self._login("osquery.view_distributedquery")
        response = self.client.get(
            reverse("osquery:distributed_query_machines", args=(distributed_query.pk,)),
            {'serial_number': serial_search}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquerymachine_list.html")
        self.assertContains(response, "1 Machine")
        self.assertContains(response, serial_search)
        for serial_number in serial_numbers[1:]:
            self.assertNotContains(response, serial_number)

    def test_distributed_query_machines_serial_search_error(self):
        distributed_query = self._force_distributed_query()
        dqm_count = 3
        serial_numbers = [get_random_string(12) for _ in range(dqm_count)]
        err_msgs = [f"Error Message {i}" if i > 0 else None for i in range(dqm_count)]
        dqm_gen = (
            DistributedQueryMachine(
                distributed_query=distributed_query,
                serial_number=serial_numbers[i],
                status=i,
                error_message=err_msgs[i],
            ) for i in range(dqm_count)
        )
        DistributedQueryMachine.objects.bulk_create(dqm_gen)
        self._login("osquery.view_distributedquery")
        response = self.client.get(
            reverse("osquery:distributed_query_machines", args=(distributed_query.pk,)), {'status': 'on'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedquerymachine_list.html")
        self.assertContains(response, "2 Machines")
        for serial_number in serial_numbers[1:]:
            self.assertContains(response, serial_number)
        self.assertContains(response, err_msgs[-1])

    # distributed query results

    def test_distributed_query_results_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:distributed_query_results", args=(distributed_query.pk,)))

    def test_distributed_query_results_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:distributed_query_results", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.osquery.views.distributed_queries.DistributedQueryResultListView.get_paginate_by")
    def test_distributed_query_results(self, get_paginate_by):
        get_paginate_by.return_value = 1
        distributed_query = self._force_distributed_query()
        dqr_count = 4
        serial_numbers = [get_random_string(12) for _ in range(dqr_count)]
        dqr_gen = (
            DistributedQueryResult(
                distributed_query=distributed_query,
                serial_number=serial_numbers[i],
                row={"un": get_random_string(12)}
            ) for i in range(dqr_count)
        )
        DistributedQueryResult.objects.bulk_create(dqr_gen)
        self._login("osquery.view_distributedqueryresult")
        response = self.client.get(reverse("osquery:distributed_query_results", args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/distributedqueryresult_list.html")
        self.assertContains(response, f"{dqr_count} Results")
        self.assertContains(response, serial_numbers[-1])
        self.assertContains(response, f"page 1 of {dqr_count}")
        search_term = serial_numbers[0] + get_random_string(12)
        response = self.client.get(
            "{}?q={}".format(reverse("osquery:distributed_query_results", args=(distributed_query.pk,)),
                             search_term)
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, search_term)
        self.assertContains(response, "0 Results")
        search_term = serial_numbers[0]
        response = self.client.get(
            "{}?q={}".format(reverse("osquery:distributed_query_results", args=(distributed_query.pk,)),
                             search_term)
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1 Result")

    # distributed query file carving sessions

    def test_distributed_query_file_carving_sessions_redirect(self):
        distributed_query = self._force_distributed_query()
        self._login_redirect(reverse("osquery:distributed_query_file_carving_sessions", args=(distributed_query.pk,)))

    def test_distributed_query_file_carving_sessions_permission_denied(self):
        distributed_query = self._force_distributed_query()
        self._login()
        response = self.client.get(reverse("osquery:distributed_query_file_carving_sessions",
                                           args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.osquery.views.distributed_queries."
           "DistributedQueryFileCarvingSessionListView.get_paginate_by")
    def test_distributed_query_file_carving_sessions(self, get_paginate_by):
        get_paginate_by.return_value = 1
        distributed_query = self._force_distributed_query()
        fcs_count = 5
        serial_numbers = [get_random_string(12) for _ in range(fcs_count)]
        fcs_gen = (
            FileCarvingSession(
                id=uuid.uuid4(),
                distributed_query=distributed_query,
                serial_number=serial_numbers[i],
                carve_guid=str(uuid.uuid4()),
                block_size=8472,
                block_count=17,
                carve_size=8499,
            ) for i in range(fcs_count)
        )
        FileCarvingSession.objects.bulk_create(fcs_gen)
        self._login("osquery.view_distributedquery", "osquery.view_filecarvingsession")
        response = self.client.get(reverse("osquery:distributed_query_file_carving_sessions",
                                           args=(distributed_query.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/dq_filecarvingsession_list.html")
        self.assertContains(response, f"{fcs_count} File carving sessions")
        self.assertContains(response, serial_numbers[-1])
        self.assertContains(response, "0/17")
        self.assertContains(response, f"page 1 of {fcs_count}")
