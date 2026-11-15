import uuid
from unittest.mock import Mock, patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from tests.zentral_test_utils.tag_any_machine_case import TagAnyMachineAPISaveCase, TagAnyMachineFormSaveCase
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.dep_client import DEVICE_BATCH_SIZE
from zentral.contrib.mdm.models import DEPEnrollment, OTAEnrollment, RealmGroupTagMapping, UserEnrollment
from zentral.contrib.mdm.skip_keys import skippable_setup_panes

from .utils import (
    force_acme_issuer,
    force_dep_enrollment,
    force_dep_virtual_server,
    force_ota_enrollment,
    force_push_certificate,
    force_realm,
    force_realm_group,
    force_realm_group_tag_mapping,
    force_scep_issuer,
    force_user_enrollment,
)


# The objects of the MDM module that give tags to machines later: the enrollments and the realm group tag mappings.


class MDMTagAnyMachineCase:
    enrollment_model = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.service_account = User.objects.create(username=get_random_string(12),
                                                  email=f"{get_random_string(12)}@zentral.io",
                                                  is_service_account=True)
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    def _get_api_key(self):
        return self.api_key

    def tam_saved_tags(self, response=None, obj=None):
        if obj is None:
            obj = self.enrollment_model.objects.get(name=self.name)
        return set(EnrollmentSecret.objects.get(pk=obj.enrollment_secret_id).tags.all())


class MDMEnrollmentFormCase(MDMTagAnyMachineCase, TagAnyMachineFormSaveCase):
    tam_form_name = "enrollment_secret_form"
    create_url_name = None
    update_url_name = None

    def form_data(self, obj=None):
        raise NotImplementedError

    def tam_create(self, tags):
        self.client.force_login(self.user)
        data = self.form_data()
        self.name = next(value for key, value in data.items() if key.endswith("-name"))
        data["es-tags"] = [tag.pk for tag in tags]
        return self.client.post(reverse(f"mdm:{self.create_url_name}"), data)

    def tam_update(self, obj, tags, omit_tags=False):
        self.client.force_login(self.user)
        data = self.form_data(obj)
        data["es-tags"] = [tag.pk for tag in tags]
        return self.client.post(reverse(f"mdm:{self.update_url_name}", args=(obj.pk,)), data)

    def tam_get_update_form(self, obj):
        self.client.force_login(self.user)
        return self.client.get(reverse(f"mdm:{self.update_url_name}", args=(obj.pk,)))


# OTA enrollments


class OTAEnrollmentAPITestCase(MDMTagAnyMachineCase, TagAnyMachineAPISaveCase, TestCase, LoginCase, RequestCase):
    enrollment_model = OTAEnrollment
    tam_permissions = ("mdm.add_otaenrollment", "mdm.change_otaenrollment")
    tam_error_path = ("enrollment_secret", "tags")

    def payload(self, tags, omit_tags=False):
        self.name = get_random_string(12)
        secret = {"meta_business_unit": self.mbu.pk}
        if not omit_tags:
            secret["tags"] = [tag.pk for tag in tags]
        return {"enrollment_secret": secret,
                "name": self.name,
                "push_certificate": force_push_certificate().pk,
                "acme_issuer": str(force_acme_issuer().pk),
                "scep_issuer": str(force_scep_issuer().pk)}

    def tam_create(self, tags):
        return self.post(reverse("mdm_api:ota_enrollments"), self.payload(tags))

    def tam_force_object(self, tags):
        enrollment = force_ota_enrollment(self.mbu)
        enrollment.enrollment_secret.tags.set(tags)
        return enrollment

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse("mdm_api:ota_enrollment", args=(obj.pk,)), self.payload(tags, omit_tags))


class OTAEnrollmentFormTestCase(MDMEnrollmentFormCase, TestCase, LoginCase):
    enrollment_model = OTAEnrollment
    tam_permissions = ("mdm.add_otaenrollment", "mdm.change_otaenrollment")
    create_url_name = "create_ota_enrollment"
    update_url_name = "update_ota_enrollment"

    def form_data(self, obj=None):
        return {"oe-name": obj.name if obj else get_random_string(12),
                "oe-display_name": get_random_string(12),
                "oe-acme_issuer": (obj.acme_issuer if obj else force_acme_issuer()).pk,
                "oe-scep_issuer": (obj.scep_issuer if obj else force_scep_issuer()).pk,
                "oe-push_certificate": (obj.push_certificate if obj else force_push_certificate()).pk,
                "es-meta_business_unit": self.mbu.pk}

    def tam_force_object(self, tags):
        enrollment = force_ota_enrollment(self.mbu)
        enrollment.enrollment_secret.tags.set(tags)
        return enrollment


# user enrollments


class UserEnrollmentFormTestCase(MDMEnrollmentFormCase, TestCase, LoginCase):
    enrollment_model = UserEnrollment
    tam_permissions = ("mdm.add_userenrollment", "mdm.change_userenrollment")
    create_url_name = "create_user_enrollment"
    update_url_name = "update_user_enrollment"

    def form_data(self, obj=None):
        return {"ue-realm": (obj.realm if obj else force_realm()).pk,
                "ue-name": obj.name if obj else get_random_string(12),
                "ue-display_name": get_random_string(12),
                "ue-acme_issuer": (obj.acme_issuer if obj else force_acme_issuer()).pk,
                "ue-scep_issuer": (obj.scep_issuer if obj else force_scep_issuer()).pk,
                "ue-push_certificate": (obj.push_certificate if obj else force_push_certificate()).pk,
                "es-meta_business_unit": self.mbu.pk}

    def tam_force_object(self, tags):
        enrollment = force_user_enrollment(self.mbu)
        enrollment.enrollment_secret.tags.set(tags)
        return enrollment


# DEP enrollments


class DEPEnrollmentAPITestCase(MDMTagAnyMachineCase, TagAnyMachineAPISaveCase, TestCase, LoginCase, RequestCase):
    enrollment_model = DEPEnrollment
    tam_permissions = ("mdm.add_depenrollment", "mdm.change_depenrollment")
    tam_error_path = ("enrollment_secret", "tags")

    def setUp(self):
        super().setUp()
        add_profile = self.enterContext(patch("zentral.contrib.mdm.dep_client.DEPClient.add_profile"))
        add_profile.side_effect = lambda *args, **kwargs: {"devices": {}, "profile_uuid": str(uuid.uuid4())}

    def payload(self, tags, omit_tags=False, virtual_server=None):
        self.name = get_random_string(12)
        secret = {"meta_business_unit": self.mbu.pk}
        if not omit_tags:
            secret["tags"] = [tag.pk for tag in tags]
        return {"display_name": get_random_string(12),
                "name": self.name,
                "push_certificate": str(force_push_certificate().pk),
                "acme_issuer": str(force_acme_issuer().pk),
                "scep_issuer": str(force_scep_issuer().pk),
                "virtual_server": (virtual_server or force_dep_virtual_server()).pk,
                "enrollment_secret": secret,
                "skip_setup_items": [key for key, _ in skippable_setup_panes],
                "is_mdm_removable": True,
                "is_supervised": False,
                "ios_max_version": "1.2.3",
                "ios_min_version": "1.2.3",
                "macos_max_version": "1.2.3",
                "macos_min_version": "1.2.3"}

    def tam_create(self, tags):
        return self.post(reverse("mdm_api:dep_enrollments"), self.payload(tags))

    def tam_force_object(self, tags):
        return force_dep_enrollment(self.mbu, tags=tags)

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse("mdm_api:dep_enrollment", args=(obj.pk,)),
                        self.payload(tags, omit_tags, obj.virtual_server))


class DEPEnrollmentFormTestCase(MDMEnrollmentFormCase, TestCase, LoginCase):
    enrollment_model = DEPEnrollment
    tam_permissions = ("mdm.add_depenrollment", "mdm.change_depenrollment")
    create_url_name = "create_dep_enrollment"
    update_url_name = "update_dep_enrollment"

    def setUp(self):
        super().setUp()
        client = Mock()
        client.get_device_batch_size.return_value = DEVICE_BATCH_SIZE
        client.add_profile.side_effect = lambda *args, **kwargs: {
            "profile_uuid": str(uuid.uuid4()).upper().replace("-", ""), "devices": {}
        }
        self.enterContext(
            patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server", return_value=client)
        )
        self.enterContext(patch("zentral.contrib.mdm.views.dep_enrollments.define_dep_profile_task"))

    def form_data(self, obj=None):
        return {"de-name": obj.name if obj else get_random_string(12),
                "de-display_name": get_random_string(12),
                "de-acme_issuer": force_acme_issuer().pk,
                "de-scep_issuer": (obj.scep_issuer if obj else force_scep_issuer()).pk,
                "de-push_certificate": (obj.push_certificate if obj else force_push_certificate()).pk,
                "de-virtual_server": (obj.virtual_server if obj else force_dep_virtual_server()).pk,
                "de-is_mdm_removable": "on",
                "de-is_supervised": "",
                "de-ios_min_version": "12.3.1",
                "de-macos_max_version": "15",
                "de-admin_full_name": "yolo",
                "de-admin_short_name": "fomo",
                "de-admin_password_complexity": 3,
                "de-admin_password_rotation_delay": 60,
                "de-admin_password": "1234",
                "de-await_device_configured": "on",
                "de-ssp-Accessibility": "on",
                "es-meta_business_unit": self.mbu.pk}

    def tam_force_object(self, tags):
        return force_dep_enrollment(self.mbu, tags=tags)


# realm group tag mappings


class RealmGroupTagMappingFormTestCase(MDMTagAnyMachineCase, TagAnyMachineFormSaveCase, TestCase, LoginCase):
    tam_permissions = ("mdm.add_realmgrouptagmapping", "mdm.change_realmgrouptagmapping")
    tam_many = False
    tam_field_name = "tag"

    def data(self, realm_group, tags):
        data = {"realm_group": realm_group.pk}
        if tags:
            data["tag"] = tags[0].pk
        return data

    def tam_create(self, tags):
        self.client.force_login(self.user)
        self.realm_group = force_realm_group()
        return self.client.post(reverse("mdm:create_realm_group_tag_mapping"), self.data(self.realm_group, tags))

    def tam_force_object(self, tags):
        return force_realm_group_tag_mapping(tag=tags[0])

    def tam_update(self, obj, tags, omit_tags=False):
        self.client.force_login(self.user)
        return self.client.post(reverse("mdm:update_realm_group_tag_mapping", args=(obj.pk,)),
                                self.data(obj.realm_group, tags))

    def tam_get_update_form(self, obj):
        self.client.force_login(self.user)
        return self.client.get(reverse("mdm:update_realm_group_tag_mapping", args=(obj.pk,)))

    def tam_saved_tags(self, response=None, obj=None):
        if obj is None:
            mappings = RealmGroupTagMapping.objects.filter(realm_group=self.realm_group)
        else:
            mappings = RealmGroupTagMapping.objects.filter(pk=obj.pk)
        return {mapping.tag for mapping in mappings}

    # a mapping always has a tag

    def test_tam_create_without_tag_without_the_action(self):
        self.tam_set_policies(tag_action=False)
        response = self.tam_create([])
        self.assertEqual(response.context["form"].errors, {"tag": ["This field is required."]})

    def test_tam_update_remove_the_tags_without_the_action(self):
        obj = self.tam_force_object([self.tam_force_tag()])
        self.tam_set_policies(tag_action=False)
        response = self.tam_update(obj, [])
        self.assertEqual(response.context["form"].errors, {"tag": ["This field is required."]})
