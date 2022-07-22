from unittest.mock import patch, Mock
import platform
from django.test import SimpleTestCase
from base.utils import deployment_info, DeploymentInfo


class TestDeploymentInfo(SimpleTestCase):
    maxDiff = None

    @patch("base.utils.platform.node")
    def test_node(self, platform_node):
        platform_node.return_value = "1234567890"
        di = DeploymentInfo()
        self.assertEqual(di.node, "1234567890")
        self.assertEqual(di.items_for_display, [("node", "1234567890")])

    def test_unknown_user_agent(self):
        di = DeploymentInfo()
        self.assertEqual(di.user_agent, "Zentral/unknown")

    @patch("base.utils.DeploymentInfo._get_deployment_module")
    def test_user_agent(self, get_deployment_module):
        deployment_module = Mock()
        deployment_module.version = "v2022.1"
        get_deployment_module.return_value = deployment_module
        di = DeploymentInfo()
        self.assertEqual(di.user_agent, "Zentral/v2022.1")

    @patch("base.utils.DeploymentInfo._get_deployment_module")
    def test_deployment_module(self, get_deployment_module):
        deployment_module = Mock()
        deployment_module.version = "v2022.1"
        deployment_module.instance_id = "instance-1"
        deployment_module.image_id = "image-1"
        deployment_module.setup_at = "2022-07-22T15:31:40"
        get_deployment_module.return_value = deployment_module
        di = DeploymentInfo()
        self.assertEqual(di.version, "v2022.1")
        self.assertEqual(di.instance_id, "instance-1")
        self.assertEqual(di.image_id, "image-1")
        self.assertEqual(di.setup_at, "2022-07-22T15:31:40")
        self.assertEqual(
            di.items_for_display,
            [("version", "v2022.1"),
             ("instance", "instance-1"),
             ("image", "image-1"),
             ("setup", "2022-07-22T15:31:40"),
             ("node", di.node)]
        )

    @patch("base.utils.DeploymentInfo._get_deployment_module")
    def test_deployment_module_empty_values(self, get_deployment_module):
        deployment_module = Mock()
        deployment_module.version = None
        deployment_module.instance_id = ""
        deployment_module.image_id = "     "
        deployment_module.setup_at = "2022-07-22T15:31:40"
        get_deployment_module.return_value = deployment_module
        di = DeploymentInfo()
        self.assertEqual(di.version, None)
        self.assertEqual(di.instance_id, "")
        self.assertEqual(di.image_id, "")
        self.assertEqual(di.setup_at, "2022-07-22T15:31:40")
        self.assertEqual(
            di.items_for_display,
            [("setup", "2022-07-22T15:31:40"),
             ("node", di.node)]
        )

    @patch("base.utils.DeploymentInfo._get_deployment_module")
    def test_node_dedup(self, get_deployment_module):
        deployment_module = Mock()
        deployment_module.instance_id = platform.node()
        get_deployment_module.return_value = deployment_module
        di = DeploymentInfo()
        # node absent because instance_id/instance has the same value
        self.assertNotIn("node", dict(di.items_for_display))

    def test_lazy_deployment_info(self):
        self.assertEqual(deployment_info.node, platform.node())
