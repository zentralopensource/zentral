from graphlib import TopologicalSorter
import inspect
import logging
from django.apps import apps
from django.db import transaction
from zentral.conf import ConfigDict, settings
from .apps import ZentralAppConfig


logger = logging.getLogger("zentral.utils.provisioning")


class Provisioner:
    config_key = None
    serializer_class = None
    depends_on = ()

    def __init__(self, app_config, settings):
        self.app_config = app_config
        self.settings = settings
        assert self.config_key is not None
        assert self.serializer_class is not None

    @property
    def model(self):
        return self.serializer_class.Meta.model

    def get_instance_by_uid(self, uid):
        try:
            return self.model.objects.select_for_update().get(provisioning_uid=uid)
        except self.model.DoesNotExist:
            pass

    @property
    def app_settings(self):
        return self.settings.get("apps", {}).get(self.app_config.name, {})

    def iter_uid_spec(self):
        provisioning_d = self.app_settings.get("provisioning")
        if not provisioning_d:
            return
        for uid, spec in provisioning_d.get(self.config_key, {}).items():
            if isinstance(spec, ConfigDict):
                spec = spec.serialize()
            yield uid, spec

    def create_instance(self, uid, spec):
        logger.info("Create %s instance %s", self.model, uid)
        serializer = self.serializer_class(data=spec)
        try:
            serializer.is_valid(raise_exception=True)
            instance = serializer.save(provisioning_uid=uid)
        except Exception:
            logger.exception("Could not create %s instance %s", self.model, uid)
        else:
            logger.info("%s instance %s created. PK: %s", self.model, uid, instance.pk)
            return instance

    def update_instance(self, instance, uid, spec):
        logger.info("Update %s instance %s", self.model, uid)
        serializer = self.serializer_class(instance, data=spec)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
        except Exception:
            logger.exception("Could not update %s instance %s", self.model, uid)
        else:
            logger.info("%s instance %s updated. PK: %s", self.model, uid, instance.pk)

    def create_or_update_instance(self, uid, spec):
        instance = self.get_instance_by_uid(uid)
        if instance:
            self.update_instance(instance, uid, spec)
        else:
            self.create_instance(uid, spec)

    def apply(self):
        for uid, spec in self.iter_uid_spec():
            self.create_or_update_instance(uid, spec)


# provisioning tools


def iter_provisioners():
    provisioner_app_configs = {}
    topological_sorter = TopologicalSorter()
    for app_config in apps.app_configs.values():
        if not isinstance(app_config, ZentralAppConfig):
            continue
        if not app_config.provisioning_module:
            continue
        for _, provisioner_cls in inspect.getmembers(
            app_config.provisioning_module,
            lambda m: (
                # only classes
                inspect.isclass(m)
                # subclasses of Provisioner
                and issubclass(m, Provisioner)
                # directly from the module (not imported)
                and m.__module__ == app_config.provisioning_module.__name__
            )
        ):
            provisioner_app_configs[provisioner_cls] = app_config
            topological_sorter.add(provisioner_cls, *provisioner_cls.depends_on)
    topological_sorter.prepare()
    while topological_sorter.is_active():
        for provisioner_cls in topological_sorter.get_ready():
            yield provisioner_cls(provisioner_app_configs[provisioner_cls], settings)
            topological_sorter.done(provisioner_cls)


def provision():
    with transaction.atomic():
        for provisioner in iter_provisioners():
            provisioner.apply()
