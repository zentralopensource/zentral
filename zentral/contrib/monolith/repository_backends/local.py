import os.path
from django.http import FileResponse, HttpResponseNotFound
from .base import BaseRepository


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)
        self.root = config["root"]

    def serialize_for_event(self):
        d = super().serialize_for_event()
        d["root"] = self.root
        return d

    def get_all_catalog_local_path(self):
        return os.path.join(self.root, "catalogs", "all")

    def download_all_catalog(self):
        return self.get_all_catalog_local_path()

    def make_munki_repository_response(self, section, name, cache_server=None):
        filepath = os.path.join(self.root, section, name)
        if not os.path.isfile(filepath):
            return HttpResponseNotFound("not found")
        else:
            return FileResponse(open(filepath, 'rb'))
