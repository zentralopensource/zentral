from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Taxonomy
from zentral.contrib.jamf.models import JamfInstance, TagConfig


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class JamfSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])

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

    def _force_jamf_instance(self):
        return JamfInstance.objects.create(
            host="{}.example.com".format(get_random_string(12)),
            port=443,
            path="/JSSResource",
            user=get_random_string(),
            password=get_random_string(),
        )

    def _force_tag_config(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        return TagConfig.objects.create(instance=jamf_instance,
                                        source="GROUP",
                                        taxonomy=t,
                                        regex=r"^YOLOFOMO: (.*)$",
                                        replacement=r"\1")

    # jamf instances

    def test_jamf_instances_redirect(self):
        self._login_redirect(reverse("jamf:jamf_instances"))

    def test_jamf_instances_permission_denied(self):
        self._login()
        response = self.client.get(reverse("jamf:jamf_instances"))
        self.assertEqual(response.status_code, 403)

    def test_jamf_instances_view(self):
        self._login("jamf.view_jamfinstance")
        response = self.client.get(reverse("jamf:jamf_instances"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_list.html")
        self.assertContains(response, "0 jamf instances")

    # create jamf instance

    def test_create_jamf_instance_redirect(self):
        self._login_redirect(reverse("jamf:create_jamf_instance"))

    def test_create_jamf_instance_permission_denied(self):
        self._login()
        response = self.client.get(reverse("jamf:create_jamf_instance"))
        self.assertEqual(response.status_code, 403)

    def test_create_jamf_instance_get(self):
        self._login("jamf.add_jamfinstance")
        response = self.client.get(reverse("jamf:create_jamf_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_form.html")
        self.assertContains(response, "Create jamf instance")

    def test_create_jamf_instance_post(self):
        self._login("jamf.add_jamfinstance", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:create_jamf_instance"),
                                    {"host": "yo.example.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd"},
                                    follow=True)
        self.assertEqual(response.template_name, ["jamf/jamfinstance_detail.html"])
        self.assertContains(response, "0 Tag configs")
        jamf_instance = response.context["object"]
        self.assertEqual(jamf_instance.version, 0)
        self.assertContains(response, "https://yo.example.com:8443/JSSResource")
        self.assertContains(response, "godzilla")
        self.assertNotContains(response, "pwd")

    # delete jamf instance

    def test_delete_jamf_instance_redirect(self):
        jamf_instance = self._force_jamf_instance()
        self._login_redirect(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)))

    def test_delete_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self._login()
        response = self.client.get(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_jamf_instance_get(self):
        jamf_instance = self._force_jamf_instance()
        self._login("jamf.delete_jamfinstance")
        response = self.client.get(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)))
        self.assertContains(response, "Delete jamf instance")

    # TODO: def test_delete_jamf_instance_post(self):
    # PB: API calls!

    # setup jamf instance

    def test_setup_jamf_instance_redirect(self):
        jamf_instance = self._force_jamf_instance()
        self._login_redirect(reverse("jamf:setup_jamf_instance", args=(jamf_instance.pk,)))

    def test_setup_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self._login()
        response = self.client.get(reverse("jamf:setup_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    # update jamf instance

    def test_update_jamf_instance_redirect(self):
        jamf_instance = self._force_jamf_instance()
        self._login_redirect(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)))

    def test_update_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self._login()
        response = self.client.get(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_jamf_instance_get(self):
        jamf_instance = self._force_jamf_instance()
        self._login("jamf.change_jamfinstance")
        response = self.client.get(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)))
        self.assertContains(response, "Update jamf instance")

    def test_update_jamf_instance_post(self):
        jamf_instance = self._force_jamf_instance()
        self._login("jamf.change_jamfinstance", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)),
                                    {"host": "yo.example2.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "0 Tag configs")
        self.assertContains(response, "https://yo.example2.com:8443/JSSResource")
        jamf_instance2 = response.context["object"]
        self.assertEqual(jamf_instance, jamf_instance2)
        self.assertEqual(jamf_instance2.version, 1)

    # create tag config

    def test_create_tag_config_redirect(self):
        jamf_instance = self._force_jamf_instance()
        self._login_redirect(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)))

    def test_create_tag_config_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self._login()
        response = self.client.get(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_tag_config_permission_get(self):
        jamf_instance = self._force_jamf_instance()
        self._login("jamf.add_tagconfig")
        response = self.client.get(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/tagconfig_form.html")

    def test_create_tag_config(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        regex = r"^YOLOFOMO: (.*)$"
        self._login("jamf.add_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)),
                                    {"source": "GROUP",
                                     "taxonomy": t.pk,
                                     "regex": regex,
                                     "replacement": r"\1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "1 Tag config")
        self.assertContains(response, t.name)

    def test_create_tag_config_error(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        regex = r"^YOLOFOMO: ("
        self._login("jamf.add_tagconfig")
        response = self.client.post(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)),
                                    {"source": "GROUP",
                                     "taxonomy": t.pk,
                                     "regex": regex,
                                     "replacement": r"\1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/tagconfig_form.html")
        self.assertContains(response, "Not a valid regex")

    # update tag config

    def test_update_tag_config_redirect(self):
        tag_config = self._force_tag_config()
        self._login_redirect(reverse("jamf:create_tag_config", args=(tag_config.instance.pk,)))

    def test_update_tag_config_permission_denied(self):
        tag_config = self._force_tag_config()
        self._login()
        response = self.client.get(reverse("jamf:create_tag_config", args=(tag_config.instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_tag_config(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self._login("jamf.change_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:update_tag_config", args=(jamf_instance.pk, tag_config.pk)),
                                    {"source": "GROUP",
                                     "taxonomy": tag_config.taxonomy.pk,
                                     "regex": tag_config.regex,
                                     "replacement": r"haha: \1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "1 Tag config")
        self.assertContains(response, "haha")

    # delete tag config

    def test_delete_tag_config_redirect(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self._login_redirect(reverse("jamf:delete_tag_config", args=(jamf_instance.pk, tag_config.pk)))

    def test_delete_tag_config_permission_denied(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self._login()
        response = self.client.get(reverse("jamf:delete_tag_config", args=(jamf_instance.pk, tag_config.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_tag_config(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self._login("jamf.delete_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:delete_tag_config", args=(jamf_instance.pk, tag_config.pk)),
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "0 Tag configs")
