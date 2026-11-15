from django.test import TestCase

from pbac.engine import engine


# the Terraform state holds each secret that the provider wrote


class TerraformStateViewTestCase(TestCase):
    def test_view_state_admin_only(self):
        action = engine.legacy_perm_actions["terraform.view_state"]
        self.assertEqual([str(group) for group in action.parents],
                         ['Terraform::Action::"AdminActions"', 'Action::"GlobalAdminActions"'])
