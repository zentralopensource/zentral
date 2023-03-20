import os.path
from django.http import HttpResponseRedirect
import requests
from zentral.contrib.monolith.exceptions import RepositoryError
from .base import BaseRepository


class Repository(BaseRepository):
    def __init__(self, config):
        super().__init__(config)
        self.root = config["root"]

    def get_all_catalog_content(self):
        r = requests.get(os.path.join(self.root, "catalogs/all"))
        if not r.status_code == 200:
            raise RepositoryError
        return r.content

    def make_munki_repository_response(self, section, name, cache_server=None):
        url = os.path.join(self.root, section, name)
        if cache_server:
            url = cache_server.get_cache_url(url)
        return HttpResponseRedirect(url)
