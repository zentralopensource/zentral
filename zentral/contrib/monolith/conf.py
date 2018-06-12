from importlib import import_module
from django.utils.functional import cached_property
from zentral.conf import settings
from zentral.utils.osx_package import get_package_builders


class MonolithConf(object):
    def app_config(self):
        return settings['apps']['zentral.contrib.monolith'].copy()

    def get_default_managed_installs(self):
        return list(self.app_config().get("default_managed_installs", []))

    @cached_property
    def repository(self):
        repository_cfg = self.app_config()['munki_repository']
        repository_class_name = "Repository"
        module = import_module(repository_cfg.pop('backend'))
        repository_class = getattr(module, repository_class_name)
        return repository_class(repository_cfg)

    @cached_property
    def enrollment_package_builders(self):
        package_builders = get_package_builders()
        enrollment_package_builders = {}
        ep_cfg = self.app_config()['enrollment_package_builders']
        for builder, builder_cfg in ep_cfg.items():
            builder_cfg = builder_cfg.copy()
            builder_cfg["class"] = package_builders[builder]
            enrollment_package_builders[builder] = builder_cfg
        return enrollment_package_builders


monolith_conf = MonolithConf()
