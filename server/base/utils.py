import platform
from django.utils.functional import SimpleLazyObject


class DeploymentInfo:
    def __init__(self):
        self.network_name = platform.node()
        self.items_for_display = []
        try:
            import base.deployment as deployment
        except ImportError:
            deployment = None
        for attr, attr_for_display in (("version", "version"),
                                       ("instance_id", "instance"),
                                       ("image_id", "image"),
                                       ("setup_at", "setup")):
            if deployment is not None:
                val = getattr(deployment, attr, None)
            else:
                val = None
            setattr(self, attr, val)
            if val is not None:
                self.items_for_display.append((attr_for_display, val))
        self.user_agent = "Zentral/{}".format(self.version or "unknown")


deployment_info = SimpleLazyObject(lambda: DeploymentInfo())
