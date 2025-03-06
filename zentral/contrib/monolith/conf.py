from datetime import datetime, timedelta
import logging
import threading
from django.utils.functional import cached_property, SimpleLazyObject
from zentral.conf import settings
from zentral.utils.osx_package import get_package_builders
from base.notifier import notifier
from .repository_backends import load_repository_backend


logger = logging.getLogger("zentral.contrib.monolith.conf")


class MonolithConf:
    reload_interval = timedelta(hours=1)

    def __init__(self):
        self._lock = threading.Lock()
        self._notifier_callback_registered = False
        self._repositories = {}
        self._repositories_last_loaded_at = None

    def _reset_repositories(self, *args, **kwargs):
        logger.info("Reset repositories")
        self._repositories_last_loaded_at = None

    def _reload_repositories(self):
        logger.info("Reload repositories")
        # avoid circular dependencies
        from .models import Repository
        with self._lock:
            try:
                repositories = list(Repository.objects.select_related("meta_business_unit").all())
            except Exception:
                logger.exception("Could not get repositories from DB")
                return
            self._repositories = {}
            for repository in repositories:
                self._repositories[repository.pk] = load_repository_backend(repository)
                logger.info("Repository %s loaded", repository)
            self._repositories_last_loaded_at = datetime.utcnow()
            if not self._notifier_callback_registered:
                # first time
                notifier.add_callback("monolith.repository", self._reset_repositories)
                self._notifier_callback_registered = True

    def get_repository(self, pk):
        if (
            self._repositories_last_loaded_at is None
            or datetime.utcnow() - self._repositories_last_loaded_at > self.reload_interval
            or pk not in self._repositories
        ):
            self._reload_repositories()
        with self._lock:
            return self._repositories[pk]

    @cached_property
    def enrollment_package_builders(self):
        package_builders = get_package_builders()
        enrollment_package_builders = {}
        epb_cfg = settings['apps']['zentral.contrib.monolith'].get('enrollment_package_builders')
        if epb_cfg:
            for builder, builder_cfg in epb_cfg.serialize().items():
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


monolith_conf = SimpleLazyObject(lambda: MonolithConf())
