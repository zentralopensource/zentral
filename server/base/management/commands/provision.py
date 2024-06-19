import inspect
import logging
from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import transaction
from zentral.conf import settings
from zentral.utils.apps import ZentralAppConfig
from zentral.utils.provisioning import Provisioner


logger = logging.getLogger("zentral.server.base.management.commands.provision")


class Command(BaseCommand):
    help = 'Provision Zentral'

    @staticmethod
    def add_arguments(parser):
        pass

    def iter_provisiners(self):
        for app_config in apps.app_configs.values():
            if not isinstance(app_config, ZentralAppConfig):
                continue
            if not app_config.provisioning_module:
                continue
            for _, provisioner_cls in inspect.getmembers(
                app_config.provisioning_module,
                lambda m: inspect.isclass(m) and m != Provisioner and issubclass(m, Provisioner)
            ):
                yield provisioner_cls(app_config, settings)

    def handle(self, *args, **options):
        with transaction.atomic():
            for provisioner in self.iter_provisiners():
                provisioner.apply()
