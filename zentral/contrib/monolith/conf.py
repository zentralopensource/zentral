from importlib import import_module
from django.utils.functional import cached_property
from zentral.conf import settings
from zentral.utils.osx_package import get_package_builders


class MonolithConf(object):
    def app_config(self):
        return settings['apps']['zentral.contrib.monolith'].copy()

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
        ep_cfg = self.app_config()['enrollment_package_builders'].serialize()
        for builder, builder_cfg in ep_cfg.items():
            requires = builder_cfg.get("requires")
            if not requires:
                requires = []
            elif isinstance(requires, str):
                requires = [requires]
            elif not isinstance(requires, list):
                raise ValueError("Unknown requires format")
            builder_cfg["requires"] = requires
            builder_cfg["class"] = package_builders[builder]
            enrollment_package_builders[builder] = builder_cfg
        return enrollment_package_builders


monolith_conf = MonolithConf()
