import os
from dateutil import parser
import requests
import shutil
import tempfile
from zentral.utils.local_dir import get_and_create_local_dir


class Releases(object):
    GITHUB_API_URL = "https://api.github.com/repos/munki/munki/releases"

    def __init__(self):
        self.release_dir = None

    def _get_release_version(self, release):
        return release["tag_name"].strip("v")

    def _get_release_asset(self, release):
        for asset in release["assets"]:
            asset_name = asset["name"]
            if asset_name.endswith(".pkg"):
                return asset_name, asset["browser_download_url"]
        raise ValueError("Could not find pkg")

    def _get_local_path(self, filename):
        if not self.release_dir:
            self.release_dir = get_and_create_local_dir("munki", "releases")
        return os.path.join(self.release_dir, filename)

    def _download_package(self, download_url, local_path):
        tmp_fh, tmp_path = tempfile.mkstemp(suffix=self.__module__)
        resp = requests.get(download_url, stream=True)
        with os.fdopen(tmp_fh, "wb") as f:
            for chunk in resp.iter_content(64 * 2**10):
                f.write(chunk)
        shutil.move(tmp_path, local_path)

    def get_versions(self):
        resp = requests.get(self.GITHUB_API_URL)
        for release in resp.json():
            try:
                filename, download_url = self._get_release_asset(release)
            except ValueError:
                continue
            version = self._get_release_version(release)
            created_at = parser.parse(release["created_at"])
            is_local = os.path.exists(self._get_local_path(filename))
            yield filename, version, created_at, download_url, is_local

    def get_requested_package(self, requested_filename):
        local_path = self._get_local_path(requested_filename)
        if not os.path.exists(local_path):
            for filename, version, created_at, download_url, _ in self.get_versions():
                if filename == requested_filename:
                    self._download_package(download_url, local_path)
                    break
        return local_path
