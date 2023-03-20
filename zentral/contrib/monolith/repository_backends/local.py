import os.path
from django.http import FileResponse, HttpResponseNotFound
from .base import BaseRepository


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)
        self.root = config["root"]

    def get_all_catalog_content(self):
        with open(os.path.join(self.root, "catalogs", "all"), "rb") as f:
            return f.read()

    def make_munki_repository_response(self, section, name, cache_server=None):
        filepath = os.path.join(self.root, section, name)
        if not os.path.isfile(filepath):
            return HttpResponseNotFound("not found")
        else:
            return FileResponse(open(filepath, 'rb'))
