from functools import reduce
import operator
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import User
from zentral.contrib.inventory.compliance_checks import InventoryJMESPathCheck
from zentral.contrib.inventory.models import JMESPathCheck
from zentral.core.compliance_checks.models import ComplianceCheck


class ComplianceChecksViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
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

    def _force_jmespath_check(self, source_name=None, profile_uuid=None, jmespath_expression=None, tags=None):
        if profile_uuid is None:
            profile_uuid = str(uuid.uuid4())
        if jmespath_expression is None:
            jmespath_expression = f"contains(profiles[*].uuid, `{profile_uuid}`)"
        cc = ComplianceCheck.objects.create(
            name=get_random_string(12),
            model=InventoryJMESPathCheck.get_model(),
        )
        jmespath_check = JMESPathCheck.objects.create(
            compliance_check=cc,
            source_name=source_name or get_random_string(12),
            jmespath_expression=jmespath_expression
        )
        if tags is not None:
            jmespath_check.tags.set(tags)
        return jmespath_check

    # redirect

    def test_redirect_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,)))

    def test_redirect_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_redirect(self):
        cc = self._force_jmespath_check()
        self._login("compliance_checks.view_compliancecheck", "inventory.view_jmespathcheck")
        response = self.client.get(reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,)))
        self.assertRedirects(response, cc.get_absolute_url())

    def test_redirect_404(self):
        cc = self._force_jmespath_check()
        cc.delete()  # the compliance check still exists
        self._login("compliance_checks.view_compliancecheck", "inventory.view_jmespathcheck")
        response = self.client.get(reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,)))
        self.assertEqual(response.status_code, 404)
