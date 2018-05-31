from importlib import import_module
from django.utils.functional import cached_property
from zentral.conf import settings


class MonolithConf(object):
    @cached_property
    def repository(self):
        repository_cfg = settings['apps']['zentral.contrib.monolith']['munki_repository'].copy()
        repository_class_name = "Repository"
        module = import_module(repository_cfg.pop('backend'))
        repository_class = getattr(module, repository_class_name)
        return repository_class(repository_cfg)

    @cached_property
    def enrollment_package_builders(self):
        # TODO: import pb via osx_package and EnrollmentForm that requires MetaBusinessUnit
        from zentral.utils.osx_package import get_package_builders
        package_builders = get_package_builders()
        enrollment_package_builders = {}
        ep_cfg = settings['apps']['zentral.contrib.monolith']['enrollment_package_builders']
        for builder, builder_cfg in ep_cfg.items():
            builder_cfg = builder_cfg.copy()
            builder_cfg["class"] = package_builders[builder]
            enrollment_package_builders[builder] = builder_cfg
        return enrollment_package_builders


monolith_conf = MonolithConf()
