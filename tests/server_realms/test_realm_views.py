import html
import operator
from functools import reduce
from io import BytesIO
from unittest.mock import Mock, patch

from accounts.models import User
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from ldap import LDAPError
from realms.backends.registry import backend_classes
from realms.models import (
    Realm,
    RealmAuthenticationSession,
    RealmGroupMapping,
    RoleMapping,
)

from .utils import (
    force_group,
    force_realm,
    force_realm_authentication_session,
    force_realm_group,
    force_realm_group_mapping,
    force_realm_user,
    force_role_mapping,
    force_user,
)


class RealmViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # ui user
        cls.ui_user = User.objects.create_user(get_random_string(12),
                                               "{}@zentral.io".format(get_random_string(12)),
                                               get_random_string(12),
                                               is_superuser=False)
        # ui group
        cls.ui_group = Group.objects.create(name=get_random_string(12))
        cls.ui_user.groups.set([cls.ui_group])

    # auth utils

    def login_redirect(self, url_name, *args):
        url = reverse("realms:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def permission_denied(self, url_name, *args):
        url = reverse("accounts:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.ui_group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.ui_group.permissions.clear()
        self.client.force_login(self.ui_user)

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_zero_links(self):
        self.login("realms.add_realm")
        response = self.client.get(reverse("realms:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/index.html")
        for view_name in ("list", "groups", "users", "realm_group_mappings", "role_mappings"):
            self.assertNotContains(response, reverse(f"realms:{view_name}"))

    def test_index_all_links(self):
        self.login(
            "realms.view_realm",
            "realms.view_realmgroup",
            "realms.view_realmuser",
            "realms.view_realmgroupmapping",
            "realms.view_rolemapping"
        )
        response = self.client.get(reverse("realms:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/index.html")
        for view_name in ("list", "groups", "users", "realm_group_mappings", "role_mappings"):
            self.assertContains(response, reverse(f"realms:{view_name}"))

    # realm list

    def test_realm_list_redirect(self):
        self.login_redirect("list")

    def test_realm_list_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 403)

    def test_realm_list_local_no_perms_no_create_links(self):
        self.login("realms.view_realm")
        realm = force_realm()
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_list.html")
        self.assertContains(response, realm.name)
        slugs = sorted(backend_classes.keys())
        self.assertEqual(slugs, ['ldap', 'openidc', 'saml'])
        for slug in backend_classes.keys():
            self.assertNotContains(response, reverse("realms:create", args=(slug,)))

    @patch("realms.middlewares.get_session")
    def test_realm_list_remote_perms_no_create_links(self, get_session):
        realm, realm_user = force_realm_user()
        ras = RealmAuthenticationSession.objects.create(realm=realm, user=realm_user, callback="")
        get_session.return_value = ras
        self.login("realms.view_realm", "realms.add_realm")
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_list.html")
        self.assertContains(response, realm.name)
        slugs = sorted(backend_classes.keys())
        self.assertEqual(slugs, ['ldap', 'openidc', 'saml'])
        for slug in backend_classes.keys():
            self.assertNotContains(response, reverse("realms:create", args=(slug,)))

    def test_realm_list_local_perms_create_links(self):
        self.login("realms.view_realm", "realms.add_realm")
        realm = force_realm()
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_list.html")
        self.assertContains(response, realm.name)
        slugs = sorted(backend_classes.keys())
        self.assertEqual(slugs, ['ldap', 'openidc', 'saml'])
        for slug in backend_classes.keys():
            self.assertContains(response, reverse("realms:create", args=(slug,)))

    # create realm

    def test_create_realm_redirect(self):
        self.login_redirect("create", "ldap")

    def test_create_realm_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:create", args=("openidc",)))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_remote_user_permission_denied(self):
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.add_realm")
        response = self.client.get(reverse("realms:create", args=("saml",)))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_get(self):
        self.login("realms.add_realm")
        response = self.client.get(reverse("realms:create", args=("saml",)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")

    def test_create_realm_get_unknown_backend(self):
        self.login("realms.add_realm")
        response = self.client.get(reverse("realms:create", args=("yolo",)))
        self.assertEqual(response.status_code, 404)

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_create_ldap_realm_post(self, get_ldap_connection):
        conn = Mock()
        get_ldap_connection.return_value = conn
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "username_claim", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        self.login("realms.add_realm", "realms.view_realm")
        response = self.client.post(reverse("realms:create", args=("ldap",)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertContains(response, payload["name"])
        realm = Realm.objects.get(name=payload["name"])
        self.assertEqual(realm.username_claim, payload["username_claim"])
        for k in ("host", "bind_dn", "bind_password", "users_base_dn"):
            self.assertEqual(realm.config[k], payload[k])
            self.assertContains(response, payload[k])
        get_ldap_connection.assert_called_once_with(payload["host"])
        conn.simple_bind_s.assert_called_once_with(payload["bind_dn"], payload["bind_password"])

    def test_create_openidc_realm_post(self):
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            "name": get_random_string(12),
            "username_claim": get_random_string(12),
            "login_session_expiry": 1200,
            "discovery_url": "https://example.com",
            "client_id": "1234",
            "client_secret": "5678",
            "extra_scopes": "un,deux",
        }
        self.login("realms.add_realm", "realms.view_realm")
        response = self.client.post(reverse("realms:create", args=("openidc",)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertContains(response, payload["name"])
        realm = Realm.objects.get(name=payload["name"])
        self.assertEqual(realm.login_session_expiry, payload["login_session_expiry"])
        self.assertEqual(realm.username_claim, payload["username_claim"])
        for k in ("discovery_url", "client_id", "client_secret"):
            self.assertEqual(realm.config[k], payload[k])
            self.assertContains(response, payload[k])
        self.assertEqual(realm.config["extra_scopes"], ["un", "deux"])

    def test_create_saml_realm_post_could_not_read_saml_metadata_file(self):
        self.login("realms.change_realm", "realms.view_realm")
        metadata_file = BytesIO(b"\xe9")
        metadata_file.name = "yolo.metadata"
        payload = {
            "name": get_random_string(12),
            "username_claim": get_random_string(12),
            "login_session_expiry": 1200,
            "metadata_file": metadata_file,
            "enabled_for_login": "on",
            "allow_idp_initiated_login": "on"
        }
        self.login("realms.add_realm", "realms.view_realm")
        response = self.client.post(reverse("realms:create", args=("saml",)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertFormError(response.context["form"], "metadata_file", "Could not read SAML metadata file")

    @patch("realms.backends.saml.forms.Saml2Client.prepare_for_authenticate")
    @patch("realms.backends.saml.forms.Saml2Config.load")
    def test_create_saml_realm_post(self, load, prepare_for_authenticate):
        self.login("realms.change_realm", "realms.view_realm")
        metadata_file = BytesIO(b"yolo")
        metadata_file.name = "yolo.metadata"
        payload = {
            "name": get_random_string(12),
            "username_claim": get_random_string(12),
            "login_session_expiry": 1200,
            "metadata_file": metadata_file,
            "enabled_for_login": "on",
            "allow_idp_initiated_login": "on"
        }
        self.login("realms.add_realm", "realms.view_realm")
        response = self.client.post(reverse("realms:create", args=("saml",)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertContains(response, payload["name"])
        realm = Realm.objects.get(name=payload["name"])
        self.assertEqual(realm.login_session_expiry, payload["login_session_expiry"])
        self.assertEqual(realm.username_claim, payload["username_claim"])
        self.assertEqual(realm.config["idp_metadata"], "yolo")
        self.assertEqual(realm.config["allow_idp_initiated_login"], True)

    @patch("realms.backends.saml.forms.Saml2Client.prepare_for_authenticate")
    @patch("realms.backends.saml.forms.Saml2Config.load")
    def test_create_saml_realm_post_with_error(self, load, prepare_for_authenticate):
        self.login("realms.change_realm", "realms.view_realm")
        metadata_file = BytesIO(b"yolo")
        metadata_file.name = "yolo.metadata"
        payload = {
            "name": get_random_string(12),
            "username_claim": get_random_string(12),
            "login_session_expiry": 1200,
            "allow_idp_initiated_login": "on"
        }
        self.login("realms.add_realm", "realms.view_realm")
        response = self.client.post(reverse("realms:create", args=("saml",)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertContains(
            response,
            html.escape("'Allow IDP initiated login' only available if 'Enable for login' or 'User portal' is set")
        )

    # view realm

    def test_view_realm_redirect(self):
        realm = force_realm()
        self.login_redirect("view", realm.pk)

    def test_view_realm_permission_denied(self):
        realm = force_realm()
        self.login()
        response = self.client.get(reverse("realms:view", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_realm_no_link(self):
        realm = force_realm()
        self.login("realms.view_realm")
        response = self.client.get(reverse("realms:view", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertNotContains(response, reverse("realms:create_realm_group_mapping"))
        self.assertNotContains(response, reverse("realms:create_role_mapping"))

    def test_view_realm_all_links(self):
        realm = force_realm()
        rmg = force_realm_group_mapping(realm=realm)
        rm = force_role_mapping(realm=realm)
        self.login(
            "realms.view_realm",
            "realms.add_realmgroupmapping",
            "realms.view_realmgroupmapping",
            "realms.add_rolemapping",
            "realms.view_rolemapping",
            "realms.change_realmgroupmapping",
            "realms.change_rolemapping",
        )
        response = self.client.get(reverse("realms:view", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertContains(response, reverse("realms:create_realm_group_mapping"))
        self.assertContains(response, reverse("realms:update_realm_group_mapping", args=(rmg.pk,)))
        self.assertContains(response, reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertContains(response, reverse("realms:create_role_mapping"))

    # update realm

    def test_update_realm_redirect(self):
        realm = force_realm()
        self.login_redirect("update", realm.pk)

    def test_update_realm_permission_denied(self):
        realm = force_realm()
        self.login()
        response = self.client.get(reverse("realms:update", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_remote_user_permission_denied(self):
        realm = force_realm()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.change_realm")
        response = self.client.get(reverse("realms:update", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_get(self):
        realm = force_realm()
        self.login("realms.change_realm")
        response = self.client.get(reverse("realms:update", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_update_realm_post(self, get_ldap_connection):
        conn = Mock()
        get_ldap_connection.return_value = conn
        realm = force_realm()
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        payload["username_claim"] = realm.username_claim
        response = self.client.post(reverse("realms:update", args=(realm.pk,)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        realm.refresh_from_db()
        self.assertEqual(realm.name, payload["name"])
        self.assertContains(response, payload["name"])
        for k in ("host", "bind_dn", "bind_password", "users_base_dn"):
            self.assertEqual(realm.config[k], payload[k])
            self.assertContains(response, payload[k])
        get_ldap_connection.assert_called_once_with(payload["host"])
        conn.simple_bind_s.assert_called_once_with(payload["bind_dn"], payload["bind_password"])

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_update_realm_post_connection_ldap_error(self, get_ldap_connection):
        get_ldap_connection.side_effect = LDAPError({"info": "Yolo"})
        realm = force_realm()
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        payload["username_claim"] = realm.username_claim
        response = self.client.post(reverse("realms:update", args=(realm.pk,)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertFormError(response.context["form"], "host", "Yolo")

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_update_realm_post_connection_unknown_error(self, get_ldap_connection):
        get_ldap_connection.side_effect = Exception("Fomo")
        realm = force_realm()
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        payload["username_claim"] = realm.username_claim
        response = self.client.post(reverse("realms:update", args=(realm.pk,)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertFormError(response.context["form"], "host", "Fomo")

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_update_realm_post_simple_bind_ldap_error(self, get_ldap_connection):
        conn = Mock()
        conn.simple_bind_s.side_effect = LDAPError({"desc": "Yolo"})
        get_ldap_connection.return_value = conn
        realm = force_realm()
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        payload["username_claim"] = realm.username_claim
        response = self.client.post(reverse("realms:update", args=(realm.pk,)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertFormError(response.context["form"], "bind_password", "Yolo")

    @patch("realms.backends.ldap.forms.get_ldap_connection")
    def test_update_realm_post_simple_bind_unknown_error(self, get_ldap_connection):
        conn = Mock()
        conn.simple_bind_s.side_effect = Exception("Fomo")
        get_ldap_connection.return_value = conn
        realm = force_realm()
        self.login("realms.change_realm", "realms.view_realm")
        payload = {
            k: get_random_string(12)
            for k in ("name", "host", "bind_dn", "bind_password", "users_base_dn")
        }
        payload["username_claim"] = realm.username_claim
        response = self.client.post(reverse("realms:update", args=(realm.pk,)), payload, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_form.html")
        self.assertFormError(response.context["form"], "bind_password", "Fomo")

    # realm group mappings

    def test_realm_group_mappings_redirect(self):
        self.login_redirect("realm_group_mappings")

    def test_realm_group_mappings_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:realm_group_mappings"))
        self.assertEqual(response.status_code, 403)

    def test_realm_group_mappings(self):
        rgm = force_realm_group_mapping()
        self.login("realms.view_realmgroupmapping")
        response = self.client.get(reverse("realms:realm_group_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        self.assertContains(response, rgm.realm_group.realm.name)
        self.assertContains(response, rgm.realm_group.display_name)
        self.assertNotContains(response, rgm.realm_group.realm.get_absolute_url())
        self.assertNotContains(response, rgm.realm_group.get_absolute_url())
        self.assertNotContains(response, reverse("realms:create_realm_group_mapping"))
        self.assertNotContains(response, reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertNotContains(response, reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)))

    def test_realm_group_mappings_all_perms(self):
        rgm = force_realm_group_mapping()
        self.login(
            "realms.view_realmgroupmapping",
            "realms.add_realmgroupmapping",
            "realms.change_realmgroupmapping",
            "realms.delete_realmgroupmapping",
            "realms.view_realm",
            "realms.view_realmgroup",
        )
        response = self.client.get(reverse("realms:realm_group_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        self.assertContains(response, rgm.realm_group.realm.name)
        self.assertContains(response, rgm.realm_group.display_name)
        self.assertContains(response, rgm.realm_group.realm.get_absolute_url())
        self.assertContains(response, rgm.realm_group.get_absolute_url())
        self.assertContains(response, reverse("realms:create_realm_group_mapping"))
        self.assertContains(response, reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertContains(response, reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)))

    # create realm group mapping

    def test_create_realm_group_mapping_redirect(self):
        self.login_redirect("create_realm_group_mapping")

    def test_create_realm_group_mapping_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:create_realm_group_mapping"))
        self.assertEqual(response.status_code, 403)

    @patch("realms.middlewares.get_session")
    def test_create_realm_group_mapping_remote_user_permission_denied(self, get_session):
        realm, realm_user = force_realm_user()
        ras = RealmAuthenticationSession.objects.create(realm=realm, user=realm_user, callback="")
        get_session.return_value = ras
        self.login("realms.add_realmgroupmapping")
        response = self.client.get(reverse("realms:create_realm_group_mapping"))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_group_mapping_get(self):
        self.login("realms.add_realmgroupmapping")
        response = self.client.get(reverse("realms:create_realm_group_mapping"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_form.html")

    def test_create_realm_group_mapping_post_no_separator_no_view_perm(self):
        realm_group = force_realm_group()
        self.login("realms.add_realmgroupmapping", "realms.view_realmgroupmapping")
        response = self.client.post(
            reverse("realms:create_realm_group_mapping"),
            {"claim": "Yolo",
             "value": "Fomo",
             "realm_group": realm_group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        rgm_qs = RealmGroupMapping.objects.all()
        self.assertEqual(rgm_qs.count(), 1)
        rgm = rgm_qs.first()
        self.assertEqual(rgm.realm_group, realm_group)
        self.assertEqual(rgm.separator, "")
        self.assertContains(response, realm_group.realm.name)
        self.assertContains(response, realm_group.display_name)
        self.assertNotContains(response, reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertNotContains(response, realm_group.realm.get_absolute_url())
        self.assertNotContains(response, realm_group.get_absolute_url())

    def test_create_realm_group_mapping_post_separator_view_perm(self):
        self.login(
            "realms.add_realmgroupmapping",
            "realms.change_realmgroupmapping",
            "realms.view_realm",
            "realms.view_realmgroup",
            "realms.view_realmgroupmapping"
        )
        realm_group = force_realm_group()
        separator = get_random_string(13)
        response = self.client.post(
            reverse("realms:create_realm_group_mapping"),
            {"claim": "Yolo",
             "separator": separator,
             "value": "Fomo",
             "realm_group": realm_group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        rgm_qs = RealmGroupMapping.objects.all()
        self.assertEqual(rgm_qs.count(), 1)
        rgm = rgm_qs.first()
        self.assertEqual(rgm.realm_group, realm_group)
        self.assertEqual(rgm.separator, separator)
        self.assertContains(response, realm_group.realm.name)
        self.assertContains(response, realm_group.display_name)
        self.assertContains(response, reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertContains(response, realm_group.realm.get_absolute_url())
        self.assertContains(response, realm_group.get_absolute_url())

    # update realm group mapping

    def test_update_realm_group_mapping_redirect(self):
        rgm = force_realm_group_mapping()
        self.login_redirect("update_realm_group_mapping", rgm.pk)

    def test_update_realm_group_mapping_permission_denied(self):
        rgm = force_realm_group_mapping()
        self.login()
        response = self.client.get(reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_group_mapping_remote_user_permission_denied(self):
        rgm = force_realm_group_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.change_realmgroupmapping")
        response = self.client.get(reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_group_mapping_get(self):
        rgm = force_realm_group_mapping()
        self.login("realms.change_realmgroupmapping")
        response = self.client.get(reverse("realms:update_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_form.html")

    def test_update_realm_group_mapping_post(self):
        rgm = force_realm_group_mapping()
        self.login(
            "realms.change_realmgroupmapping",
            "realms.view_realmgroupmapping"
        )
        realm_group = force_realm_group()
        separator = get_random_string(13)
        response = self.client.post(
            reverse("realms:update_realm_group_mapping", args=(rgm.pk,)),
            {"claim": "Yolo",
             "separator": separator,
             "value": "Fomo",
             "realm_group": realm_group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        rgm_qs = RealmGroupMapping.objects.all()
        self.assertEqual(rgm_qs.count(), 1)
        self.assertEqual(rgm_qs.first(), rgm)
        rgm.refresh_from_db()
        self.assertEqual(rgm.realm_group, realm_group)
        self.assertEqual(rgm.separator, separator)

    # delete realm group mapping

    def test_delete_realm_group_mapping_redirect(self):
        rgm = force_realm_group_mapping()
        self.login_redirect("delete_realm_group_mapping", rgm.pk)

    def test_delete_realm_group_mapping_permission_denied(self):
        rgm = force_realm_group_mapping()
        self.login()
        response = self.client.get(reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_group_mapping_remote_user_permission_denied(self):
        rgm = force_realm_group_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.delete_realmgroupmapping")
        response = self.client.get(reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_group_mapping_get(self):
        rgm = force_realm_group_mapping()
        self.login("realms.delete_realmgroupmapping")
        response = self.client.get(reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_confirm_delete.html")

    def test_delete_realm_group_mapping_post(self):
        rgm = force_realm_group_mapping()
        self.login("realms.delete_realmgroupmapping", "realms.view_realmgroupmapping")
        response = self.client.post(reverse("realms:delete_realm_group_mapping", args=(rgm.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_list.html")
        rgm_qs = RealmGroupMapping.objects.all()
        self.assertEqual(rgm_qs.count(), 0)

    # role mappings

    def test_role_mappings_redirect(self):
        self.login_redirect("role_mappings")

    def test_role_mappings_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:role_mappings"))
        self.assertEqual(response.status_code, 403)

    def test_role_mappings(self):
        rm = force_role_mapping()
        self.login("realms.view_rolemapping")
        response = self.client.get(reverse("realms:role_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_list.html")
        self.assertContains(response, rm.realm_group.realm.name)
        self.assertContains(response, rm.realm_group.display_name)
        self.assertContains(response, rm.group.name)
        self.assertNotContains(response, rm.realm_group.realm.get_absolute_url())
        self.assertNotContains(response, rm.realm_group.get_absolute_url())
        self.assertNotContains(response, reverse("accounts:group", args=(rm.group.pk,)))
        self.assertNotContains(response, reverse("realms:create_role_mapping"))
        self.assertNotContains(response, reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertNotContains(response, reverse("realms:delete_role_mapping", args=(rm.pk,)))

    def test_role_mappings_all_perms(self):
        rm = force_role_mapping()
        self.login(
            "auth.view_group",
            "realms.view_rolemapping",
            "realms.add_rolemapping",
            "realms.change_rolemapping",
            "realms.delete_rolemapping",
            "realms.view_realm",
            "realms.view_realmgroup",
        )
        response = self.client.get(reverse("realms:role_mappings"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_list.html")
        self.assertContains(response, rm.realm_group.realm.name)
        self.assertContains(response, rm.realm_group.display_name)
        self.assertContains(response, rm.group.name)
        self.assertContains(response, rm.realm_group.realm.get_absolute_url())
        self.assertContains(response, rm.realm_group.get_absolute_url())
        self.assertContains(response, reverse("accounts:group", args=(rm.group.pk,)))
        self.assertContains(response, reverse("realms:create_role_mapping"))
        self.assertContains(response, reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertContains(response, reverse("realms:delete_role_mapping", args=(rm.pk,)))

    # create role mapping

    def test_create_role_mapping_redirect(self):
        self.login_redirect("create_role_mapping")

    def test_create_role_mapping_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:create_role_mapping"))
        self.assertEqual(response.status_code, 403)

    @patch("realms.middlewares.get_session")
    def test_create_role_mapping_remote_user_permission_denied(self, get_session):
        realm, realm_user = force_realm_user()
        ras = RealmAuthenticationSession.objects.create(realm=realm, user=realm_user, callback="")
        get_session.return_value = ras
        self.login("realms.add_rolemapping")
        response = self.client.get(reverse("realms:create_role_mapping"))
        self.assertEqual(response.status_code, 403)

    def test_create_role_mapping_get(self):
        self.login("realms.add_rolemapping")
        response = self.client.get(reverse("realms:create_role_mapping"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_form.html")

    def test_create_role_mapping_no_view_perm(self):
        group = force_group()
        realm_group = force_realm_group()
        self.login("realms.add_rolemapping", "realms.view_rolemapping")
        response = self.client.post(
            reverse("realms:create_role_mapping"),
            {"group": group.pk,
             "realm_group": realm_group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_list.html")
        rm_qs = RoleMapping.objects.all()
        self.assertEqual(rm_qs.count(), 1)
        rm = rm_qs.first()
        self.assertEqual(rm.group, group)
        self.assertEqual(rm.realm_group, realm_group)
        self.assertContains(response, realm_group.realm.name)
        self.assertContains(response, realm_group.display_name)
        self.assertContains(response, group.name)
        self.assertNotContains(response, reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertNotContains(response, realm_group.realm.get_absolute_url())
        self.assertNotContains(response, realm_group.get_absolute_url())
        self.assertNotContains(response, reverse("accounts:group", args=(group.pk,)))

    # update role mapping

    def test_update_role_mapping_redirect(self):
        rm = force_role_mapping()
        self.login_redirect("update_role_mapping", rm.pk)

    def test_update_role_mapping_permission_denied(self):
        rm = force_role_mapping()
        self.login()
        response = self.client.get(reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_role_mapping_remote_user_permission_denied(self):
        rm = force_role_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.change_rolemapping")
        response = self.client.get(reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_role_mapping_get(self):
        rm = force_role_mapping()
        self.login("realms.change_rolemapping")
        response = self.client.get(reverse("realms:update_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_form.html")

    def test_update_role_mapping_post(self):
        rm = force_role_mapping()
        self.login(
            "realms.change_rolemapping",
            "realms.view_rolemapping"
        )
        group = force_group()
        realm_group = force_realm_group()
        response = self.client.post(
            reverse("realms:update_role_mapping", args=(rm.pk,)),
            {"group": group.pk,
             "realm_group": realm_group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_list.html")
        rm_qs = RoleMapping.objects.all()
        self.assertEqual(rm_qs.count(), 1)
        self.assertEqual(rm_qs.first(), rm)
        rm.refresh_from_db()
        self.assertEqual(rm.group, group)
        self.assertEqual(rm.realm_group, realm_group)

    # delete role mapping

    def test_delete_role_mapping_redirect(self):
        rm = force_role_mapping()
        self.login_redirect("delete_role_mapping", rm.pk)

    def test_delete_role_mapping_permission_denied(self):
        rm = force_role_mapping()
        self.login()
        response = self.client.get(reverse("realms:delete_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_role_mapping_remote_user_permission_denied(self):
        rm = force_role_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.delete_rolemapping")
        response = self.client.get(reverse("realms:delete_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_role_mapping_get(self):
        rm = force_role_mapping()
        self.login("realms.delete_rolemapping")
        response = self.client.get(reverse("realms:delete_role_mapping", args=(rm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_confirm_delete.html")

    def test_delete_role_mapping_post(self):
        rm = force_role_mapping()
        self.login("realms.delete_rolemapping", "realms.view_rolemapping")
        response = self.client.post(reverse("realms:delete_role_mapping", args=(rm.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/rolemapping_list.html")
        rm_qs = RoleMapping.objects.all()
        self.assertEqual(rm_qs.count(), 0)

    # realm groups

    def test_realm_groups_redirect(self):
        self.login_redirect("groups")

    def test_realm_groups_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:groups"))
        self.assertEqual(response.status_code, 403)

    def test_realm_groups(self):
        self.login("realms.view_realmgroup")
        group = force_realm_group()
        response = self.client.get(reverse("realms:groups"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_list.html")
        self.assertContains(response, group.display_name)
        self.assertContains(response, group.get_absolute_url())
        self.assertContains(response, "Group (1)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_realm_groups_no_results(self):
        self.login("realms.view_realmgroup")
        group = force_realm_group()
        response = self.client.get(reverse("realms:groups"), {"display_name": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_list.html")
        self.assertNotContains(response, group.display_name)
        self.assertNotContains(response, group.get_absolute_url())
        self.assertContains(response, "Groups (0)")
        self.assertContains(response, "We didn't find any item related to your search")

    def test_realm_groups_one_result_realm_link(self):
        self.login("realms.view_realm", "realms.view_realmgroup")
        force_realm_group()
        group = force_realm_group()
        response = self.client.get(reverse("realms:groups"), {"display_name": group.display_name.upper()[:6],
                                                              "realm": group.realm.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_list.html")
        self.assertContains(response, group.display_name)
        self.assertContains(response, group.get_absolute_url())
        self.assertContains(response, group.realm.name)
        self.assertContains(response, group.realm.get_absolute_url())
        self.assertContains(response, "Group (1)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_realm_groups_one_result_no_realm_link(self):
        self.login("realms.view_realmgroup")
        force_realm_group()
        group = force_realm_group()
        response = self.client.get(reverse("realms:groups"), {"display_name": group.display_name.upper()[:6],
                                                              "realm": group.realm.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_list.html")
        self.assertContains(response, group.display_name)
        self.assertContains(response, group.get_absolute_url())
        self.assertContains(response, group.realm.name)
        self.assertNotContains(response, group.realm.get_absolute_url())
        self.assertContains(response, "Group (1)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    # realm group

    def test_realm_group_redirect(self):
        group = force_realm_group()
        self.login_redirect("group", group.pk)

    def test_realm_group_permission_denied(self):
        group = force_realm_group()
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:group", args=(group.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_realm_group_all_links(self):
        parent = force_realm_group()
        group = force_realm_group(realm=parent.realm, parent=parent)
        child = force_realm_group(realm=group.realm, parent=group)
        force_realm_user(realm=group.realm, group=group)
        self.login("realms.view_realm", "realms.view_realmgroup", "realms.view_realmuser")
        response = self.client.get(reverse("realms:group", args=(group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_detail.html")
        self.assertContains(response, group.display_name)
        self.assertContains(response, group.realm.name)
        self.assertContains(response, group.realm.get_absolute_url())
        self.assertContains(response, parent.get_absolute_url())
        self.assertContains(response, "Child (1)")
        self.assertContains(response, child.get_absolute_url())
        self.assertContains(response, "User (1)")
        self.assertContains(response, reverse("realms:users") + f"?realm={group.realm.pk}&realm_group={group.pk}")

    def test_realm_group_no_users_realm_links(self):
        group = force_realm_group()
        force_realm_user(realm=group.realm, group=group)
        self.login("realms.view_realmgroup")
        response = self.client.get(reverse("realms:group", args=(group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_detail.html")
        self.assertContains(response, group.display_name)
        self.assertContains(response, group.realm.name)
        self.assertNotContains(response, group.realm.get_absolute_url())
        self.assertContains(response, "Children (0)")
        self.assertContains(response, "User (1)")
        self.assertNotContains(response, reverse("realms:users") + f"?realm={group.realm.pk}&realm_group={group.pk}")

    # create realm group

    def test_create_realm_group_redirect(self):
        self.login_redirect("create_group")

    def test_create_realm_group_permission_denied(self):
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:create_group"))
        self.assertEqual(response.status_code, 403)

    def test_create_realm_group_get(self):
        self.login("realms.add_realmgroup")
        response = self.client.get(reverse("realms:create_group"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_form.html")
        self.assertContains(response, "Create group")

    def test_create_realm_group_post(self):
        realm = force_realm()
        display_name = get_random_string(12)
        self.login("realms.add_realmgroup", "realms.view_realmgroup")
        response = self.client.post(
            reverse("realms:create_group"),
            {"realm": realm.pk,
             "display_name": display_name},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_detail.html")
        self.assertContains(response, display_name)

    # update realm group

    def test_update_realm_group_redirect(self):
        realm_group = force_realm_group()
        self.login_redirect("update_group", realm_group.pk)

    def test_update_realm_group_permission_denied(self):
        realm_group = force_realm_group()
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:update_group", args=(realm_group.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_realm_group_get(self):
        realm_group = force_realm_group()
        self.login("realms.change_realmgroup")
        response = self.client.get(reverse("realms:update_group", args=(realm_group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_form.html")
        self.assertContains(response, "Update group")

    def test_update_realm_group_post(self):
        realm_group = force_realm_group()
        new_display_name = get_random_string(12)
        self.login("realms.change_realmgroup", "realms.view_realmgroup")
        response = self.client.post(
            reverse("realms:update_group", args=(realm_group.pk,)),
            {"display_name": new_display_name},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_detail.html")
        self.assertContains(response, new_display_name)
        realm_group.refresh_from_db()
        self.assertEqual(realm_group.display_name, new_display_name)

    # delete realm group

    def test_delete_realm_group_redirect(self):
        realm_group = force_realm_group()
        self.login_redirect("delete_group", realm_group.pk)

    def test_delete_realm_group_permission_denied(self):
        realm_group = force_realm_group()
        self.login("realms.change_realmgroup")
        response = self.client.get(reverse("realms:delete_group", args=(realm_group.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_group_get(self):
        realm_group = force_realm_group()
        self.login("realms.delete_realmgroup")
        response = self.client.get(reverse("realms:delete_group", args=(realm_group.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_confirm_delete.html")
        self.assertContains(response, "Delete group")

    def test_delete_realm_group_post(self):
        realm_group = force_realm_group()
        self.login("realms.delete_realmgroup", "realms.view_realmgroup")
        response = self.client.post(reverse("realms:delete_group", args=(realm_group.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroup_list.html")
        self.assertNotContains(response, realm_group.display_name)

    # realm users

    def test_realm_users_redirect(self):
        self.login_redirect("users")

    def test_realm_users_permission_denied(self):
        self.login("realms.view_realmgroup")
        response = self.client.get(reverse("realms:users"))
        self.assertEqual(response.status_code, 403)

    def test_realm_users(self):
        self.login("realms.view_realmuser")
        _, user = force_realm_user()
        response = self.client.get(reverse("realms:users"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_list.html")
        self.assertContains(response, user.username)
        self.assertContains(response, user.get_absolute_url())
        self.assertContains(response, "User (1)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_realm_users_no_results(self):
        self.login("realms.view_realmuser")
        _, user = force_realm_user()
        response = self.client.get(reverse("realms:users"), {"q": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_list.html")
        self.assertNotContains(response, user.username)
        self.assertNotContains(response, user.get_absolute_url())
        self.assertContains(response, "Users (0)")
        self.assertContains(response, "We didn't find any item related to your search")

    def test_realm_users_one_result_no_realm_link(self):
        self.login("realms.view_realmuser")
        group = force_realm_group()
        force_realm_user(realm=group.realm, group=group)
        _, user = force_realm_user(realm=group.realm, group=group)
        response = self.client.get(reverse("realms:users"), {"q": user.username.upper()[:6],
                                                             "realm_group": group.pk,
                                                             "realm": user.realm.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_list.html")
        self.assertContains(response, user.username)
        self.assertContains(response, user.get_absolute_url())
        self.assertContains(response, "User (1)")
        self.assertContains(response, group.realm.name)
        self.assertNotContains(response, group.realm.get_absolute_url())
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_realm_users_one_result_realm_link(self):
        self.login("realms.view_realm", "realms.view_realmuser")
        group = force_realm_group()
        force_realm_user(realm=group.realm, group=group)
        _, user = force_realm_user(realm=group.realm, group=group)
        response = self.client.get(reverse("realms:users"), {"q": user.username.upper()[:6],
                                                             "realm_group": group.pk,
                                                             "realm": user.realm.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_list.html")
        self.assertContains(response, user.username)
        self.assertContains(response, user.get_absolute_url())
        self.assertContains(response, "User (1)")
        self.assertContains(response, group.realm.name)
        self.assertContains(response, group.realm.get_absolute_url())
        self.assertNotContains(response, "We didn't find any item related to your search")

    # realm user

    def test_realm_user_redirect(self):
        _, user = force_realm_user()
        self.login_redirect("user", user.pk)

    def test_realm_user_permission_denied(self):
        _, user = force_realm_user()
        self.login("realms.view_realmgroup")
        response = self.client.get(reverse("realms:user", args=(user.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_realm_user_all_links(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login("realms.view_realm", "realms.view_realmgroup", "realms.view_realmuser")
        response = self.client.get(reverse("realms:user", args=(user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertContains(response, user.username)
        self.assertContains(response, user.email)
        self.assertContains(response, group.realm.get_absolute_url())
        self.assertContains(response, group.realm.name)
        self.assertContains(response, group.get_absolute_url())
        self.assertContains(response, group.display_name)
        self.assertContains(response, "direct")
        self.assertContains(response, "Zentral users (0)")

    def test_realm_user_no_group_realm_links(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:user", args=(user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertContains(response, user.username)
        self.assertContains(response, user.email)
        self.assertNotContains(response, group.realm.get_absolute_url())
        self.assertContains(response, group.realm.name)
        self.assertNotContains(response, group.get_absolute_url())
        self.assertContains(response, group.display_name)
        self.assertContains(response, "direct")
        self.assertContains(response, "Zentral users (0)")

    def test_realm_user_one_zentral_user_link(self):
        realm = force_realm(enabled_for_login=True)
        _, realm_user = force_realm_user(realm=realm)
        user = force_user(username=realm_user.username, email=realm_user.email)
        self.login("realms.view_realmuser", "accounts.view_user")
        response = self.client.get(reverse("realms:user", args=(realm_user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertContains(response, user.get_absolute_url())
        self.assertContains(response, "Zentral user (1)")

    def test_realm_user_one_zentral_no_user_link(self):
        realm = force_realm(enabled_for_login=True)
        _, realm_user = force_realm_user(realm=realm)
        user = force_user(username=realm_user.username, email=realm_user.email)
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:user", args=(realm_user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertNotContains(response, user.get_absolute_url())
        self.assertContains(response, "Zentral user (1)")

    # add realm user to group

    def test_add_realm_user_to_group_login_redirect(self):
        _, user = force_realm_user()
        self.login_redirect("add_user_to_group", user.pk)

    def test_add_realm_user_to_group_permission_denied(self):
        _, user = force_realm_user()
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:add_user_to_group", args=(user.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_add_realm_user_to_group_get(self):
        existing_group = force_realm_group()
        realm, user = force_realm_user(realm=existing_group.realm, group=existing_group)
        available_group = force_realm_group(realm=realm)
        scim_group = force_realm_group(realm=realm)
        scim_group.scim_managed = True
        scim_group.save()
        other_group = force_realm_group()
        self.login("realms.change_realmgroup")
        response = self.client.get(reverse("realms:add_user_to_group", args=(user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_add_to_group.html")
        self.assertNotContains(response, existing_group.display_name)
        self.assertContains(response, available_group.display_name)
        self.assertNotContains(response, scim_group.display_name)
        self.assertNotContains(response, other_group.display_name)

    @patch("realms.views.realm_group_members_updated.send_robust")
    def test_add_realm_user_to_group_post(self, send_robust):
        scim_group = force_realm_group()
        scim_group.scim_managed = True
        scim_group.save()
        realm, user = force_realm_user(realm=scim_group.realm, group=scim_group)
        group = force_realm_group(realm=realm)
        self.login("realms.change_realmgroup", "realms.view_realmuser")
        response = self.client.post(reverse("realms:add_user_to_group", args=(user.pk,)),
                                    {"realm_group": str(group.pk)},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertNotContains(response, reverse("realms:remove_user_from_group", args=(user.pk, scim_group.pk)))
        self.assertContains(response, reverse("realms:remove_user_from_group", args=(user.pk, group.pk)))
        send_robust.assert_called_once()

    # remove realm user from group

    def test_remove_realm_user_from_group_redirect(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login_redirect("remove_user_from_group", user.pk, group.pk)

    def test_remove_realm_user_from_group_permission_denied(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login("realms.view_realmuser")
        response = self.client.get(reverse("realms:remove_user_from_group", args=(user.pk, group.pk)))
        self.assertEqual(response.status_code, 403)

    def test_remove_realm_user_from_group_get(self):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login("realms.change_realmgroup")
        response = self.client.get(reverse("realms:remove_user_from_group", args=(user.pk, group.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_remove_from_group.html")

    @patch("realms.views.realm_group_members_updated.send_robust")
    def test_remove_realm_user_from_group_post(self, send_robust):
        group = force_realm_group()
        _, user = force_realm_user(realm=group.realm, group=group)
        self.login("realms.change_realmgroup", "realms.view_realmuser")
        response = self.client.post(reverse("realms:remove_user_from_group", args=(user.pk, group.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmuser_detail.html")
        self.assertNotContains(response, group.display_name)
        send_robust.assert_called_once()

    # test realm

    def test_realm_permission_denied(self):
        realm = force_realm(enabled_for_login=True)
        self.login()
        response = self.client.post(reverse("realms:test", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_realm(self):
        realm = force_realm(enabled_for_login=True)
        self.login("realms.view_realm")
        response = self.client.post(reverse("realms:test", args=(realm.pk,)))
        ras = realm.realmauthenticationsession_set.first()
        self.assertRedirects(response, reverse("realms_public:ldap_login", args=(realm.pk, ras.pk)))

    # authentication session

    def test_authentication_session_login_redirect(self):
        ras = force_realm_authentication_session()
        self.login_redirect("test", ras.realm.pk)

    def test_authentication_session_permission_denied(self):
        ras = force_realm_authentication_session()
        self.login()
        response = self.client.get(reverse("realms:authentication_session", args=(ras.realm.pk, ras.pk)))
        self.assertEqual(response.status_code, 403)

    def test_authentication_session(self):
        ras = force_realm_authentication_session()
        self.login("realms.view_realm")
        response = self.client.get(reverse("realms:authentication_session", args=(ras.realm.pk, ras.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmauthenticationsession_detail.html")
        self.assertContains(response, "IdP claims")
