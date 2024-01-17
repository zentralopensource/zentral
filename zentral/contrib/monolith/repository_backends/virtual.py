import logging
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponseNotFound, HttpResponseRedirect
from django.utils.functional import cached_property
from zentral.utils.storage import file_storage_has_signed_urls
from .base import BaseRepository


logger = logging.getLogger("zentral.contrib.monolith.repository_backends.virtual")


class VirtualRepository(BaseRepository):
    def sync_catalogs(self, audit_callback=None):
        # NOOP
        return

    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def make_munki_repository_response(self, section, name, cache_server=None):
        if section == "pkgs":
            if self._redirect_to_files:
                return HttpResponseRedirect(default_storage.url(name))
            elif default_storage.exists(name):
                return FileResponse(default_storage.open(name))
        return HttpResponseNotFound("Munki asset not found!")
