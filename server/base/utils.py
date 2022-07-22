import platform
from django.utils.functional import SimpleLazyObject


class DeploymentInfo:
    @staticmethod
    def _get_deployment_module():
        try:
            import base.deployment as deployment
        except ImportError:
            deployment = None
        return deployment

    def _add_item(self, attr, attr_for_display, val, dedup=False):
        if isinstance(val, str):
            val = val.strip()
        setattr(self, attr, val)
        if val is None or val == "":
            return
        if dedup and val in (v for _, v in self.items_for_display):
            return
        self.items_for_display.append((attr_for_display, val))

    def _add_deployment_info(self):
        deployment = self._get_deployment_module()
        for attr, attr_for_display in (("version", "version"),
                                       ("instance_id", "instance"),
                                       ("image_id", "image"),
                                       ("setup_at", "setup")):
            if deployment is not None:
                val = getattr(deployment, attr, None)
            else:
                val = None
            self._add_item(attr, attr_for_display, val)

    def _add_node(self):
        self._add_item("node", "node", platform.node(), dedup=True)

    def _add_user_agent(self):
        self.user_agent = "Zentral/{}".format(self.version or "unknown")

    def __init__(self):
        self.items_for_display = []
        self._add_deployment_info()
        self._add_node()
        self._add_user_agent()


deployment_info = SimpleLazyObject(lambda: DeploymentInfo())
