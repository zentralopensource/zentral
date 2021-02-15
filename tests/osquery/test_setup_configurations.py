from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from zentral.contrib.osquery.models import Configuration, ConfigurationPack, Pack, PackQuery, Query


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsquerySetupConfigurationsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())

    # utiliy methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string())

    def _force_pack(self):
        pack = Pack.objects.create(name=get_random_string())
        query = Query.objects.create(name=get_random_string(), sql="select 1 from processes;")
        PackQuery.objects.create(pack=pack, query=query, interval=203)
        return pack

    def _force_configuration_pack(self):
        configuration = self._force_configuration()
        pack = self._force_pack()
        return ConfigurationPack.objects.create(configuration=configuration, pack=pack)

    # create configuration

    def test_create_configuration_redirect(self):
        self._login_redirect(reverse("osquery:create_configuration"))

    def test_create_configuration_get(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("osquery:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_form.html")
        self.assertContains(response, "Create Osquery configuration")

    def test_create_configuration_post(self):
        self.client.force_login(self.user)
        configuration_name = get_random_string(64)
        response = self.client.post(reverse("osquery:create_configuration"),
                                    {"name": configuration_name, "inventory_interval": 86321},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, configuration_name)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, configuration_name)
        self.assertEqual(configuration.inventory_interval, 86321)
        self.assertEqual(configuration.options, {})

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("osquery:update_configuration", args=(configuration.pk,)))

    def test_update_configuration_get(self):
        self.client.force_login(self.user)
        configuration = self._force_configuration()
        response = self.client.get(reverse("osquery:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_form.html")
        self.assertContains(response, "Update Osquery configuration")

    def test_update_configuration_post(self):
        self.client.force_login(self.user)
        configuration = self._force_configuration()
        new_name = get_random_string(64)
        response = self.client.post(reverse("osquery:update_configuration", args=(configuration.pk,)),
                                    {"name": new_name, "inventory_interval": 863},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, new_name)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, new_name)
        self.assertEqual(configuration.inventory_interval, 863)
        self.assertEqual(configuration.options, {})

    # configuration list

    def test_configuration_list_redirect(self):
        self._login_redirect(reverse("osquery:configurations"))

    def test_configuration_list(self):
        self.client.force_login(self.user)
        configuration = self._force_configuration()
        response = self.client.get(reverse("osquery:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_list.html")
        self.assertIn(configuration, response.context["object_list"])
        self.assertContains(response, configuration.name)

    # add configuration pack

    def test_add_configuration_pack_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("osquery:add_configuration_pack", args=(configuration.pk,)))

    def test_add_configuration_pack_get(self):
        configuration = self._force_configuration()
        self.client.force_login(self.user)
        response = self.client.get(reverse("osquery:add_configuration_pack", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_form.html")
        self.assertEqual(response.context["configuration"], configuration)

    def test_add_configuration_pack_post(self):
        configuration = self._force_configuration()
        pack = self._force_pack()
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("osquery:add_configuration_pack", args=(configuration.pk,)),
            {"pack": pack.pk},
            follow=True
        )
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["configuration"], configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 1)
        configuration_pack = configuration_packs.first()
        self.assertEqual(configuration_pack.configuration, configuration)
        self.assertEqual(configuration_pack.pack, pack)
        self.assertEqual(configuration_pack.tags.count(), 0)

    # update configuration pack

    def test_update_configuration_pack_redirect(self):
        configuration_pack = self._force_configuration_pack()
        self._login_redirect(reverse("osquery:update_configuration_pack",
                                     args=(configuration_pack.configuration.pk, configuration_pack.pk)))

    def test_update_configuration_pack_get(self):
        configuration_pack = self._force_configuration_pack()
        self.client.force_login(self.user)
        response = self.client.get(reverse("osquery:update_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_form.html")
        self.assertEqual(response.context["configuration"], configuration_pack.configuration)
        self.assertEqual(response.context["object"], configuration_pack)

    def test_update_configuration_pack_post(self):
        configuration_pack = self._force_configuration_pack()
        self.client.force_login(self.user)
        tag = Tag.objects.create(name=get_random_string())
        response = self.client.post(
            reverse("osquery:update_configuration_pack",
                    args=(configuration_pack.configuration.pk, configuration_pack.pk)),
            {"pack": configuration_pack.pack.pk,
             "tags": [tag.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration_pack.configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 1)
        resp_configuration_pack = configuration_packs.first()
        self.assertEqual(resp_configuration_pack, configuration_pack)
        self.assertEqual(resp_configuration_pack.pack, configuration_pack.pack)
        self.assertEqual(list(resp_configuration_pack.tags.all()), [tag])
        self.assertContains(response, tag.name)

    # remove configuration pack

    def test_remove_configuration_pack_redirect(self):
        configuration_pack = self._force_configuration_pack()
        self._login_redirect(reverse("osquery:remove_configuration_pack",
                                     args=(configuration_pack.configuration.pk, configuration_pack.pk)))

    def test_remove_configuration_pack_get(self):
        configuration_pack = self._force_configuration_pack()
        self.client.force_login(self.user)
        response = self.client.get(reverse("osquery:remove_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_confirm_delete.html")
        self.assertEqual(response.context["object"], configuration_pack)

    def test_remove_configuration_pack_post(self):
        configuration_pack = self._force_configuration_pack()
        self.client.force_login(self.user)
        response = self.client.post(reverse("osquery:remove_configuration_pack",
                                            args=(configuration_pack.configuration.pk, configuration_pack.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration_pack.configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 0)
