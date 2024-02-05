from functools import reduce
from io import BytesIO
import operator
from ldap import LDAPError
from unittest.mock import Mock, patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from realms.models import Realm, RealmAuthenticationSession
from zentral.contrib.inventory.models import Tag
from .utils import (force_realm, force_realm_group, force_realm_group_mapping,
                    force_realm_tag_mapping, force_realm_user, force_user)


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
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

    # realm list

    def test_realm_list_redirect(self):
        self.login_redirect("list")

    def test_realm_list_permission_denied(self):
        self.login()
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 403)

    def test_realm_list(self):
        realm = force_realm()
        self.login("realms.view_realm")
        response = self.client.get(reverse("realms:list"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_list.html")
        self.assertContains(response, realm.name)

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

    # view realm

    def test_view_realm_redirect(self):
        realm = force_realm()
        self.login_redirect("view", realm.pk)

    def test_view_realm_permission_denied(self):
        realm = force_realm()
        self.login()
        response = self.client.get(reverse("realms:view", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_realm(self):
        realm = force_realm()
        self.login("realms.view_realm")
        response = self.client.get(reverse("realms:view", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")

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

    # create group mapping

    def test_create_group_mapping_redirect(self):
        realm = force_realm()
        self.login_redirect("create_group_mapping", realm.pk)

    def test_create_group_mapping_permission_denied(self):
        realm = force_realm()
        self.login()
        response = self.client.get(reverse("realms:create_group_mapping", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("realms.middlewares.get_session")
    def test_create_group_mapping_remote_user_permission_denied(self, get_session):
        realm, realm_user = force_realm_user()
        ras = RealmAuthenticationSession.objects.create(realm=realm, user=realm_user, callback="")
        get_session.return_value = ras
        self.login("realms.add_realmgroupmapping")
        response = self.client.get(reverse("realms:create_group_mapping", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_group_mapping_get(self):
        realm = force_realm()
        self.login("realms.add_realmgroupmapping")
        response = self.client.get(reverse("realms:create_group_mapping", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_form.html")

    def test_create_group_mapping_post_no_separator_no_view_perm(self):
        realm = force_realm()
        self.login("realms.add_realmgroupmapping", "realms.view_realm")
        group = Group.objects.create(name=get_random_string(12))
        response = self.client.post(
            reverse("realms:create_group_mapping", args=(realm.pk,)),
            {"realm": realm.pk,
             "claim": "Yolo",
             "value": "Fomo",
             "group": group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmgroupmapping_set.count(), 1)
        rgm = realm.realmgroupmapping_set.first()
        self.assertEqual(rgm.group, group)
        self.assertEqual(rgm.separator, "")
        self.assertNotContains(response, group.name)  # not displayed

    def test_create_group_mapping_post_separator_view_perm(self):
        realm = force_realm()
        self.login("realms.add_realmgroupmapping", "realms.view_realm", "realms.view_realmgroupmapping")
        group = Group.objects.create(name=get_random_string(12))
        separator = get_random_string(13)
        response = self.client.post(
            reverse("realms:create_group_mapping", args=(realm.pk,)),
            {"realm": realm.pk,
             "claim": "Yolo",
             "separator": separator,
             "value": "Fomo",
             "group": group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmgroupmapping_set.count(), 1)
        rgm = realm.realmgroupmapping_set.first()
        self.assertEqual(rgm.group, group)
        self.assertEqual(rgm.separator, separator)
        self.assertContains(response, group.name)  # displayed
        self.assertContains(response, separator)  # displayed

    # update group mapping

    def test_update_group_mapping_redirect(self):
        realm, rgm = force_realm_group_mapping()
        self.login_redirect("update_group_mapping", realm.pk, rgm.pk)

    def test_update_group_mapping_permission_denied(self):
        realm, rgm = force_realm_group_mapping()
        self.login()
        response = self.client.get(reverse("realms:update_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_group_mapping_remote_user_permission_denied(self):
        realm, rgm = force_realm_group_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.change_realmgroupmapping")
        response = self.client.get(reverse("realms:update_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_group_mapping_get(self):
        realm, rgm = force_realm_group_mapping()
        self.login("realms.change_realmgroupmapping")
        response = self.client.get(reverse("realms:update_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_form.html")

    def test_update_group_mapping_post(self):
        realm, rgm = force_realm_group_mapping()
        self.login("realms.change_realmgroupmapping", "realms.view_realm", "realms.view_realmgroupmapping")
        group = Group.objects.create(name=get_random_string(12))
        separator = get_random_string(13)
        response = self.client.post(
            reverse("realms:update_group_mapping", args=(realm.pk, rgm.pk)),
            {"realm": realm.pk,
             "claim": "Yolo",
             "separator": separator,
             "value": "Fomo",
             "group": group.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmgroupmapping_set.count(), 1)
        self.assertEqual(realm.realmgroupmapping_set.first(), rgm)
        rgm.refresh_from_db()
        self.assertEqual(rgm.group, group)
        self.assertEqual(rgm.separator, separator)

    # delete group mapping

    def test_delete_group_mapping_redirect(self):
        realm, rgm = force_realm_group_mapping()
        self.login_redirect("delete_group_mapping", realm.pk, rgm.pk)

    def test_delete_group_mapping_permission_denied(self):
        realm, rgm = force_realm_group_mapping()
        self.login()
        response = self.client.get(reverse("realms:delete_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_group_mapping_remote_user_permission_denied(self):
        realm, rgm = force_realm_group_mapping()
        self.ui_user.is_remote = True
        self.ui_user.save()
        self.login("realms.delete_realmgroupmapping")
        response = self.client.get(reverse("realms:update_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_group_mapping_get(self):
        realm, rgm = force_realm_group_mapping()
        self.login("realms.delete_realmgroupmapping")
        response = self.client.get(reverse("realms:delete_group_mapping", args=(realm.pk, rgm.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmgroupmapping_confirm_delete.html")

    def test_delete_group_mapping_post(self):
        realm, rgm = force_realm_group_mapping()
        self.login("realms.delete_realmgroupmapping", "realms.view_realm")
        response = self.client.post(reverse("realms:delete_group_mapping", args=(realm.pk, rgm.pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmgroupmapping_set.count(), 0)

    # create tag mapping

    def test_create_tag_mapping_redirect(self):
        realm = force_realm()
        self.login_redirect("create_tag_mapping", realm.pk)

    def test_create_tag_mapping_permission_denied(self):
        realm = force_realm()
        self.login()
        response = self.client.get(reverse("realms:create_tag_mapping", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_tag_mapping_get(self):
        realm = force_realm()
        self.login("realms.add_realmtagmapping")
        response = self.client.get(reverse("realms:create_tag_mapping", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmtagmapping_form.html")

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_create_tag_mapping_post(self, update_realm_tags):
        realm = force_realm()
        group_name = get_random_string(12)
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("realms.add_realmtagmapping", "realms.view_realm", "realms.view_realmtagmapping")
        response = self.client.post(
            reverse("realms:create_tag_mapping", args=(realm.pk,)),
            {"realm": realm.pk,
             "group_name": group_name,
             "tag": tag.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmtagmapping_set.count(), 1)
        rtm = realm.realmtagmapping_set.first()
        self.assertEqual(rtm.group_name, group_name)
        self.assertEqual(rtm.tag, tag)
        self.assertContains(response, rtm.group_name)
        self.assertContains(response, tag.name)
        update_realm_tags.assert_called_once_with(realm)

    # update tag mapping

    def test_update_tag_mapping_redirect(self):
        realm, rtm = force_realm_tag_mapping()
        self.login_redirect("update_tag_mapping", realm.pk, rtm.pk)

    def test_update_tag_mapping_permission_denied(self):
        realm, rtm = force_realm_tag_mapping()
        self.login("realms.add_realmtagmapping")
        response = self.client.get(reverse("realms:update_tag_mapping", args=(realm.pk, rtm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_tag_mapping_get(self):
        realm, rtm = force_realm_tag_mapping()
        self.login("realms.change_realmtagmapping")
        response = self.client.get(reverse("realms:update_tag_mapping", args=(realm.pk, rtm.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmtagmapping_form.html")

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_update_tag_mapping_post(self, update_realm_tags):
        realm, rtm = force_realm_tag_mapping()
        group_name = get_random_string(12)
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("realms.change_realmtagmapping", "realms.view_realm", "realms.view_realmtagmapping")
        response = self.client.post(
            reverse("realms:update_tag_mapping", args=(realm.pk, rtm.pk)),
            {"realm": realm.pk,
             "group_name": group_name,
             "tag": tag.pk},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmtagmapping_set.count(), 1)
        rtm = realm.realmtagmapping_set.first()
        self.assertEqual(rtm.group_name, group_name)
        self.assertEqual(rtm.tag, tag)
        self.assertContains(response, rtm.group_name)
        self.assertContains(response, tag.name)
        update_realm_tags.assert_called_once_with(realm)

    # delete tag mapping

    def test_delete_tag_mapping_redirect(self):
        realm, rtm = force_realm_tag_mapping()
        self.login_redirect("delete_tag_mapping", realm.pk, rtm.pk)

    def test_delete_tag_mapping_permission_denied(self):
        realm, rtm = force_realm_tag_mapping()
        self.login("realms.add_realmtagmapping")
        response = self.client.get(reverse("realms:delete_tag_mapping", args=(realm.pk, rtm.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_tag_mapping_get(self):
        realm, rtm = force_realm_tag_mapping()
        self.login("realms.delete_realmtagmapping")
        response = self.client.get(reverse("realms:delete_tag_mapping", args=(realm.pk, rtm.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realmtagmapping_confirm_delete.html")

    @patch("zentral.contrib.mdm.inventory.update_realm_tags")
    def test_delete_tag_mapping_post(self, update_realm_tags):
        realm, rtm = force_realm_tag_mapping()
        tag = Tag.objects.create(name=get_random_string(12))
        self.login("realms.delete_realmtagmapping", "realms.view_realm", "realms.view_realmtagmapping")
        response = self.client.post(reverse("realms:delete_tag_mapping", args=(realm.pk, rtm.pk)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "realms/realm_detail.html")
        self.assertEqual(realm.realmtagmapping_set.count(), 0)
        self.assertNotContains(response, rtm.group_name)
        self.assertNotContains(response, tag.name)
        update_realm_tags.assert_called_once_with(realm)

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
