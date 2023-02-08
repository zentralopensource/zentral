from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from django.utils.text import slugify
from zentral.contrib.osquery.compliance_checks import sync_query_compliance_check
from zentral.contrib.osquery.models import Pack, PackQuery, Query


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupPacksViewsTestCase(TestCase):
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

    def _force_pack(self):
        return Pack.objects.create(name=get_random_string(12))

    def _force_query(self, query_name=None, force_pack=False, force_compliance_check=False):
        if query_name:
            name = query_name
        else:
            name = get_random_string(12).lower()
        if force_compliance_check:
            sql = "select 'OK' as ztl_status;"
        else:
            sql = "select 1 from processes;"
        query = Query.objects.create(name=name, sql=sql)
        slug = slugify(query.name)
        if force_pack:
            pack = self._force_pack()
            PackQuery.objects.create(pack=pack, query=query, interval=12983, slug=slug,
                                     log_removed_actions=False, snapshot_mode=force_compliance_check)
        sync_query_compliance_check(query, force_compliance_check)
        return query

    # create pack

    def test_create_pack_redirect(self):
        self._login_redirect(reverse("osquery:create_pack"))

    def test_create_pack_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:create_pack"))
        self.assertEqual(response.status_code, 403)

    def test_create_pack_get(self):
        self._login("osquery.add_pack")
        response = self.client.get(reverse("osquery:create_pack"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_form.html")
        self.assertContains(response, "Create Pack")

    def test_create_pack_post(self):
        self._login("osquery.add_pack", "osquery.view_pack")
        pack_name = get_random_string(64)
        response = self.client.post(reverse("osquery:create_pack"), {"name": pack_name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertContains(response, pack_name)
        pack = response.context["object"]
        self.assertEqual(pack.name, pack_name)

    # update pack

    def test_update_pack_redirect(self):
        pack = self._force_pack()
        self._login_redirect(reverse("osquery:update_pack", args=(pack.pk,)))

    def test_update_pack_permission_denied(self):
        pack = self._force_pack()
        self._login()
        response = self.client.get(reverse("osquery:update_pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_pack_get(self):
        pack = self._force_pack()
        self._login("osquery.change_pack")
        response = self.client.get(reverse("osquery:update_pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_form.html")

    def test_update_pack_post(self):
        pack = self._force_pack()
        self._login("osquery.change_pack", "osquery.view_pack")
        new_name = get_random_string(12)
        response = self.client.post(reverse("osquery:update_pack", args=(pack.pk,)),
                                    {"name": new_name,
                                     "shard": 97},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertContains(response, new_name)
        pack = response.context["object"]
        self.assertEqual(pack.name, new_name)
        self.assertEqual(pack.shard, 97)

    # delete pack

    def test_delete_pack_redirect(self):
        pack = self._force_pack()
        self._login_redirect(reverse("osquery:delete_pack", args=(pack.pk,)))

    def test_delete_pack_permission_denied(self):
        pack = self._force_pack()
        self._login()
        response = self.client.get(reverse("osquery:delete_pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_get(self):
        pack = self._force_pack()
        self._login("osquery.delete_pack")
        response = self.client.get(reverse("osquery:delete_pack", args=(pack.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_confirm_delete.html")
        self.assertContains(response, pack.name)

    def test_delete_pack_post(self):
        pack = self._force_pack()
        self._login("osquery.delete_pack", "osquery.view_pack")
        response = self.client.post(reverse("osquery:delete_pack", args=(pack.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_list.html")
        self.assertEqual(Pack.objects.filter(pk=pack.pk).count(), 0)
        self.assertNotContains(response, pack.name)

    # pack list

    def test_pack_list_redirect(self):
        self._login_redirect(reverse("osquery:packs"))

    def test_pack_list_permission_denied(self):
        self._login()
        response = self.client.get(reverse("osquery:packs"))
        self.assertEqual(response.status_code, 403)

    def test_pack_list(self):
        pack = self._force_pack()
        self._login("osquery.view_pack")
        response = self.client.get(reverse("osquery:packs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_list.html")
        self.assertIn(pack, response.context["object_list"])
        self.assertContains(response, pack.name)

    # pack detail

    def test_pack_detail_redirect(self):
        pack = self._force_pack()
        self._login_redirect(pack.get_absolute_url())

    def test_pack_detail_permission_denied(self):
        pack = self._force_pack()
        self._login()
        response = self.client.get(pack.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_pack_detail(self):
        pack = self._force_pack()
        self._login("osquery.view_pack", "osquery.view_query", "osquery.add_packquery", "osquery.view_packquery")
        response = self.client.get(pack.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(pack, response.context["object"])
        self.assertContains(response, pack.name)
        self.assertNotContains(response, reverse("osquery:add_pack_query", args=(pack.pk,)))
        query = self._force_query()
        response = self.client.get(pack.get_absolute_url())
        self.assertContains(response, reverse("osquery:add_pack_query", args=(pack.pk,)))
        PackQuery.objects.create(pack=pack, query=query, interval=12983)
        response = self.client.get(pack.get_absolute_url())
        self.assertNotContains(response, reverse("osquery:add_pack_query", args=(pack.pk,)))
        self._force_query()
        response = self.client.get(pack.get_absolute_url())
        self.assertContains(response, reverse("osquery:add_pack_query", args=(pack.pk,)))

    # add pack query

    def test_add_pack_query_redirect(self):
        pack = self._force_pack()
        self._login_redirect(reverse("osquery:add_pack_query", args=(pack.pk,)))

    def test_add_pack_query_permission_denied(self):
        pack = self._force_pack()
        self._login()
        response = self.client.get(reverse("osquery:add_pack_query", args=(pack.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_add_pack_query_get(self):
        pack = self._force_pack()
        query = self._force_query()
        self._login("osquery.add_packquery")
        response = self.client.get(reverse("osquery:add_pack_query", args=(pack.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_form.html")
        self.assertEqual(response.context["pack"], pack)
        self.assertContains(response, query.name)

    def test_add_pack_query_mode_error(self):
        pack = self._force_pack()
        query = self._force_query()
        self._login("osquery.add_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:add_pack_query", args=(pack.pk,)),
                                    {"query": query.pk, "interval": 3456,
                                     "log_removed_actions": "on", "snapshot_mode": "on"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_form.html")
        self.assertFormError(response, "form", "log_removed_actions",
                             "'Log removed actions' and 'Snapshot mode' are mutually exclusive")
        self.assertFormError(response, "form", "snapshot_mode",
                             "'Log removed actions' and 'Snapshot mode' are mutually exclusive")

    def test_add_pack_query_post(self):
        pack = self._force_pack()
        query = self._force_query()
        self._login("osquery.add_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:add_pack_query", args=(pack.pk,)),
                                    {"query": query.pk, "interval": 3456}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack)
        self.assertContains(response, query.name)
        self.assertContains(response, "3456s")
        self.assertNotContains(response, "Compliance check")

    def test_add_pack_query_with_slug_conflict(self):
        query_name = get_random_string(16)
        pq = self._force_query(query_name=query_name.lower(), force_pack=True).packquery
        slug = pq.slug
        pack = pq.pack
        query = self._force_query(query_name=query_name.upper())
        self._login("osquery.add_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:add_pack_query", args=(pack.pk,)),
                                    {"query": query.pk, "interval": 3456}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack)
        self.assertContains(response, query.name)
        pack_query = PackQuery.objects.get(pack=pack, query=query)
        self.assertEqual(pack_query.slug, f"{slug}-{query.pk}")

    def test_add_pack_query_with_compliance_check_error(self):
        pack = self._force_pack()
        query = self._force_query(force_compliance_check=True)
        self._login("osquery.add_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:add_pack_query", args=(pack.pk,)),
                                    {"query": query.pk, "interval": 3456,
                                     "log_removed_actions": "on"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_form.html")
        self.assertFormError(response, "form", "snapshot_mode",
                             "A compliance check query can only be scheduled in 'snapshot' mode.")

    def test_add_pack_query_with_compliance_check(self):
        pack = self._force_pack()
        query = self._force_query(force_compliance_check=True)
        self._login("osquery.add_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:add_pack_query", args=(pack.pk,)),
                                    {"query": query.pk, "interval": 3456,
                                     "snapshot_mode": "on"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack)
        self.assertContains(response, query.name)
        self.assertContains(response, "3456s")
        self.assertContains(response, "Compliance check")

    # update pack query

    def test_update_pack_query_redirect(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login_redirect(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)))

    def test_update_pack_query_permission_denied(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login()
        response = self.client.get(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_pack_query_get(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login("osquery.change_packquery")
        response = self.client.get(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_form.html")
        self.assertEqual(response.context["pack"], pack_query.pack)
        self.assertContains(response, pack_query.interval)

    def test_update_pack_query_mode_error(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login("osquery.change_packquery")
        response = self.client.post(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)),
                                    {"query": query.pk, "interval": 12345,
                                     "log_removed_actions": "on", "snapshot_mode": "on"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_form.html")
        self.assertFormError(response, "form", "log_removed_actions",
                             "'Log removed actions' and 'Snapshot mode' are mutually exclusive")
        self.assertFormError(response, "form", "snapshot_mode",
                             "'Log removed actions' and 'Snapshot mode' are mutually exclusive")

    def test_update_pack_query_post(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login("osquery.change_packquery", "osquery.view_pack", "osquery.view_packquery")
        response = self.client.post(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)),
                                    {"query": query.pk, "interval": 12345}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack_query.pack)
        self.assertContains(response, query.name)
        self.assertContains(response, "12345s")

    def test_update_pack_query_with_compliance_check(self):
        query = self._force_query(force_pack=True, force_compliance_check=True)
        pack_query = query.packquery
        self._login("osquery.change_packquery", "osquery.view_pack", "osquery.view_packquery")
        # log_removed_actions and snapshot_mode fields are disabled
        response = self.client.post(reverse("osquery:update_pack_query", args=(pack_query.pack.pk, pack_query.pk)),
                                    {"query": query.pk, "interval": 123456}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack_query.pack)
        self.assertContains(response, query.name)
        self.assertContains(response, "123456s")

    # delete pack query

    def test_delete_pack_query_redirect(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login_redirect(reverse("osquery:delete_pack_query", args=(pack_query.pack.pk, pack_query.pk)))

    def test_delete_pack_query_permission_denied(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login()
        response = self.client.get(reverse("osquery:delete_pack_query", args=(pack_query.pack.pk, pack_query.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pack_query_get(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login("osquery.delete_packquery")
        response = self.client.get(reverse("osquery:delete_pack_query", args=(pack_query.pack.pk, pack_query.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/packquery_confirm_delete.html")
        self.assertEqual(response.context["object"], pack_query)
        self.assertContains(response, query.name)

    def test_delete_pack_query_post(self):
        query = self._force_query(force_pack=True)
        pack_query = query.packquery
        self._login("osquery.delete_packquery", "osquery.view_pack")
        response = self.client.post(reverse("osquery:delete_pack_query", args=(pack_query.pack.pk, pack_query.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/pack_detail.html")
        self.assertEqual(response.context["object"], pack_query.pack)
        self.assertNotContains(response, query.name)
        self.assertNotContains(response, f"{pack_query.interval}s")
