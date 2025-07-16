from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.puppet.models import Instance, test_report_processor_token
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision
from .utils import build_self_signed_cert


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage'
)
class PuppetSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()

    # utility methods

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

    def _force_instance(self, rbac_auth=True):
        ca_chain, _ = build_self_signed_cert("Test-CA")
        instance = Instance.objects.create(
            business_unit=self.bu,
            url="https://{}.example.com".format(get_random_string(8)),
            ca_chain=ca_chain,
        )
        instance.set_report_processor_token(get_random_string(12))
        if rbac_auth:
            instance.set_rbac_token(get_random_string(12))
        else:
            instance.cert, key = build_self_signed_cert(f"{instance.pk}-client")
            instance.set_key(key)
        instance.save()
        instance.refresh_from_db()  # for version
        return instance

    # instances

    def test_instances_redirect(self):
        self._login_redirect(reverse("puppet:instances"))

    def test_instances_permission_denied(self):
        self._login()
        response = self.client.get(reverse("puppet:instances"))
        self.assertEqual(response.status_code, 403)

    def test_instances(self):
        instance = self._force_instance()
        self._login("puppet.view_instance")
        response = self.client.get(reverse("puppet:instances"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, instance.hostname)
        self.assertNotContains(response, reverse("puppet:instance_events",
                                                 args=(instance.pk,)))
        self.assertNotContains(response, reverse("puppet:instance_events_store_redirect",
                                                 args=(instance.pk,)))

    # instance events

    def test_instance_events_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("puppet:instance_events", args=(instance.pk,)))

    def test_instance_events_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("puppet:instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.get_aggregated_object_event_counts")
    def test_instance_events_ok(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        instance = self._force_instance()
        self._login("puppet.view_instance")
        response = self.client.get(reverse("puppet:instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_events.html")

    def test_fetch_instance_events_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("puppet:fetch_instance_events", args=(instance.pk,)))

    def test_fetch_instance_events_permission_denied(self):
        instance = self._force_instance()
        self._login("puppet.change_instance")
        response = self.client.get(reverse("puppet:fetch_instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_object_events")
    def test_fetch_instance_events_ok(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        instance = self._force_instance()
        self._login("puppet.view_instance")
        response = self.client.get(reverse("puppet:fetch_instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # create instance

    def test_create_instance_redirect(self):
        self._login_redirect(reverse("puppet:create_instance"))

    def test_create_instance_permission_denied(self):
        self._login()
        response = self.client.get(reverse("puppet:create_instance"))
        self.assertEqual(response.status_code, 403)

    def test_create_instance_get(self):
        self._login("puppet.add_instance")
        response = self.client.get(reverse("puppet:create_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_form.html")

    def test_create_instance_post(self):
        self._login("puppet.add_instance", "puppet.view_instance")
        url = "https://{}.example.com".format(get_random_string(8))
        ca_chain, _ = build_self_signed_cert("CA")
        name = get_random_string(12)
        cert, key = build_self_signed_cert(name)
        response = self.client.post(reverse("puppet:create_instance"),
                                    {"business_unit": self.bu.pk,
                                     "url": url,
                                     "client_certificate_auth": "on",
                                     "cert": cert,
                                     "key": key,
                                     "ca_chain": ca_chain,
                                     "group_fact_keys": "un,  deux",
                                     "extra_fact_keys": "trois,quatre",
                                     "timeout": 8,
                                     "deb_packages_shard": 10,
                                     "programs_shard": 20,
                                     "report_heartbeat_timeout": 1234},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_detail.html")
        self.assertContains(response, url)
        instance = response.context["object"]
        self.assertContains(response, name)
        self.assertEqual(instance.url, url)
        self.assertEqual(instance.ca_chain, ca_chain)
        self.assertEqual(instance.cert, cert)
        self.assertEqual(instance.get_key(), key)
        self.assertEqual(instance.group_fact_keys, ["un", "deux"])
        self.assertEqual(instance.extra_fact_keys, ["trois", "quatre"])
        self.assertEqual(instance.deb_packages_shard, 10)
        self.assertEqual(instance.programs_shard, 20)
        self.assertEqual(instance.report_heartbeat_timeout, 1234)

    # update instance

    def test_update_instance_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("puppet:update_instance", args=(instance.pk,)))

    def test_update_instance_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("puppet:update_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_instance_get(self):
        instance = self._force_instance()
        self._login("puppet.change_instance")
        response = self.client.get(reverse("puppet:update_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_form.html")

    def test_update_rbac_token_instance_post(self):
        instance = self._force_instance(rbac_auth=False)  # instance with cert & key
        self._login("puppet.change_instance", "puppet.view_instance")
        rbac_token = get_random_string(12)
        response = self.client.post(reverse("puppet:update_instance", args=(instance.pk,)),
                                    {"business_unit": instance.business_unit.pk,
                                     "url": instance.url,
                                     "rbac_token_auth": "on",
                                     "rbac_token": rbac_token,
                                     "ca_chain": instance.ca_chain,
                                     "group_fact_keys": "un,  deux",
                                     "extra_fact_keys": "trois,quatre",
                                     "timeout": instance.timeout,
                                     "deb_packages_shard": instance.deb_packages_shard,
                                     "programs_shard": instance.programs_shard,
                                     "report_heartbeat_timeout": 1234},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_detail.html")
        instance2 = response.context["object"]
        self.assertEqual(instance2, instance)
        self.assertEqual(instance2.url, instance.url)
        self.assertEqual(instance2.group_fact_keys, ["un", "deux"])
        self.assertEqual(instance2.extra_fact_keys, ["trois", "quatre"])
        self.assertEqual(instance2.get_rbac_token(), rbac_token)
        self.assertEqual(instance2.cert, "")
        self.assertEqual(instance2.get_key(), "")
        self.assertEqual(instance2.report_heartbeat_timeout, 1234)
        # the cached info is updated using a post_save signal handler, so the following is OK:
        version, observer_dict = test_report_processor_token(instance.pk, instance.get_report_processor_token())
        self.assertNotEqual(version, instance.version)
        self.assertEqual(version, instance2.version)

    # delete instance

    def test_delete_instance_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("puppet:delete_instance", args=(instance.pk,)))

    def test_delete_instance_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("puppet:delete_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_instance_get(self):
        instance = self._force_instance()
        self._login("puppet.delete_instance")
        response = self.client.get(reverse("puppet:delete_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_confirm_delete.html")

    def test_delete_instance_post(self):
        instance = self._force_instance()
        pk = instance.pk
        token = instance.get_report_processor_token()
        version, observer_dict = test_report_processor_token(pk, token)
        self.assertEqual(version, instance.version)
        self.assertEqual(observer_dict, instance.observer_dict())
        self._login("puppet.delete_instance", "puppet.view_instance")
        response = self.client.post(reverse("puppet:delete_instance", args=(instance.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "puppet/instance_list.html")
        self.assertNotContains(response, instance.hostname)
        # the cached info is removed using a post_delete signal handler, so the following exception is raise:
        with self.assertRaises(Instance.DoesNotExist):
            test_report_processor_token(pk, token)
