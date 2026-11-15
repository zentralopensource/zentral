from importlib import import_module
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from tests.zentral_test_utils.tag_any_machine_case import TagAnyMachineAPISaveCase, TagAnyMachineFormSaveCase
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag


# The enrollments of the agents: the same secret serializer and the same secret form in each module.


class AgentEnrollmentCase:
    module = None
    parent_field = "configuration"
    create_url_name = "create_enrollment"

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
        cls.enrollment_model = import_module(f"zentral.contrib.{cls.module}.models").Enrollment

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return self.module

    def _get_api_key(self):
        return self.api_key

    def force_parent(self):
        parent_model = self.enrollment_model._meta.get_field(self.parent_field).related_model
        kwargs = {"name": get_random_string(12)}
        if self.parent_field == "manifest":
            kwargs["meta_business_unit"] = self.mbu
        return parent_model.objects.create(**kwargs)

    def tam_force_object(self, tags):
        secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        secret.tags.set(tags)
        return self.enrollment_model.objects.create(secret=secret, **{self.parent_field: self.force_parent()})

    def tam_saved_tags(self, response=None, obj=None):
        if obj is None:
            obj = self.enrollment_model.objects.get(**{self.parent_field: self.parent})
        return set(EnrollmentSecret.objects.get(pk=obj.secret_id).tags.all())


class AgentEnrollmentAPICase(AgentEnrollmentCase, TagAnyMachineAPISaveCase):
    tam_error_path = ("secret", "tags")

    @property
    def tam_permissions(self):
        return (f"{self.module}.add_enrollment", f"{self.module}.change_enrollment")

    def payload(self, parent, tags, omit_tags=False):
        secret = {"meta_business_unit": self.mbu.pk}
        if not omit_tags:
            secret["tags"] = [tag.pk for tag in tags]
        return {self.parent_field: str(parent.pk), "secret": secret}

    def tam_create(self, tags):
        self.parent = self.force_parent()
        return self.post(reverse(f"{self.module}_api:enrollments"), self.payload(self.parent, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse(f"{self.module}_api:enrollment", args=(obj.pk,)),
                        self.payload(getattr(obj, self.parent_field), tags, omit_tags))


class AgentEnrollmentFormCase(AgentEnrollmentCase, TagAnyMachineFormSaveCase):
    tam_has_update = False
    tam_form_name = "secret_form"

    @property
    def tam_permissions(self):
        return (f"{self.module}.add_enrollment",)

    def tam_create(self, tags):
        self.parent = self.force_parent()
        self.client.force_login(self.user)
        return self.client.post(reverse(f"{self.module}:{self.create_url_name}", args=(self.parent.pk,)),
                                {"secret-meta_business_unit": self.mbu.pk,
                                 "secret-tags": [tag.pk for tag in tags],
                                 self.parent_field: self.parent.pk})


class MonolithEnrollmentAPITestCase(AgentEnrollmentAPICase, TestCase, LoginCase, RequestCase):
    module = "monolith"
    parent_field = "manifest"


class MonolithEnrollmentFormTestCase(AgentEnrollmentFormCase, TestCase, LoginCase):
    module = "monolith"
    parent_field = "manifest"
    create_url_name = "add_manifest_enrollment"

    def test_tag_of_another_business_unit_not_logged(self):
        # the form narrows the tags to the business unit of the manifest: not a tagAnyMachine refusal
        tag = Tag.objects.create(name=get_random_string(12),
                                 meta_business_unit=MetaBusinessUnit.objects.create(name=get_random_string(12)))
        self.tam_set_policies()
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.tam_create([tag])
        self.assertIn("tags", response.context["secret_form"].errors)


class MunkiEnrollmentAPITestCase(AgentEnrollmentAPICase, TestCase, LoginCase, RequestCase):
    module = "munki"


class MunkiEnrollmentFormTestCase(AgentEnrollmentFormCase, TestCase, LoginCase):
    module = "munki"


class OsqueryEnrollmentAPITestCase(AgentEnrollmentAPICase, TestCase, LoginCase, RequestCase):
    module = "osquery"


class OsqueryEnrollmentFormTestCase(AgentEnrollmentFormCase, TestCase, LoginCase):
    module = "osquery"

    def setUp(self):
        super().setUp()
        self.enterContext(patch("zentral.contrib.osquery.forms.get_osquery_versions"))


class SantaEnrollmentAPITestCase(AgentEnrollmentAPICase, TestCase, LoginCase, RequestCase):
    module = "santa"


class SantaEnrollmentFormTestCase(AgentEnrollmentFormCase, TestCase, LoginCase):
    module = "santa"


class TurboEnrollmentAPITestCase(AgentEnrollmentAPICase, TestCase, LoginCase, RequestCase):
    module = "turbo"


class TurboEnrollmentFormTestCase(AgentEnrollmentFormCase, TestCase, LoginCase):
    module = "turbo"
