import logging
import os
import shutil
from subprocess import check_call
import tempfile
from dateutil import parser
import requests
from requests.exceptions import ConnectionError, HTTPError
from zentral.utils.local_dir import get_and_create_local_dir


logger = logging.getLogger("zentral.contrib.santa.releases")


class Releases(object):
    GITHUB_API_URL = "https://api.github.com/repos/google/santa/releases"

    def __init__(self):
        self.release_dir = None

    def _get_release_version(self, release):
        return release["tag_name"]

    def _get_release_asset(self, release):
        for asset in release["assets"]:
            asset_name = asset["name"]
            if asset_name.endswith(".dmg"):
                return asset_name, asset["browser_download_url"]
        raise ValueError("Could not find dmg")

    def _get_local_path(self, version):
        if not self.release_dir:
            self.release_dir = get_and_create_local_dir("santa", "releases")
        local_filename = "santa-{}.pkg".format(version)
        return os.path.join(self.release_dir, local_filename)

    def _download_and_extract_package(self, download_url, local_path):
        # downloaded file is a dmg containing a pkg
        # download file
        tempdir = tempfile.mkdtemp(suffix=self.__module__)
        resp = requests.get(download_url, stream=True)
        resp.raise_for_status()
        downloaded_file = os.path.join(tempdir, "downloaded_file")
        with open(downloaded_file, "wb") as f:
            for chunk in resp.iter_content(64 * 2**10):
                f.write(chunk)
        # extract dmg
        check_call(["/usr/bin/7z", "-o{}".format(tempdir), "x", downloaded_file])
        # find hfs (for older versions of 7z)
        for filename in os.listdir(tempdir):
            if filename.endswith(".hfs"):
                check_call(["/usr/bin/7z", "-o{}".format(tempdir), "x", os.path.join(tempdir, filename)])
                break
        # find pkg
        for root, dirs, files in os.walk(tempdir):
            for filename in files:
                if filename.endswith(".pkg"):
                    shutil.move(os.path.join(root, filename),
                                local_path)
                    break
        shutil.rmtree(tempdir)

    def get_versions(self):
        try:
            resp = requests.get(self.GITHUB_API_URL)
            resp.raise_for_status()
        except (ConnectionError, HTTPError):
            logger.exception("Could not get versions from Github.")
            return
        for release in resp.json():
            try:
                filename, download_url = self._get_release_asset(release)
            except ValueError:
                continue
            version = self._get_release_version(release)
            created_at = parser.parse(release["created_at"])
            is_local = os.path.exists(self._get_local_path(version))
            yield filename, version, created_at, download_url, is_local

    def get_requested_version(self, requested_version):
        for filename, version, created_at, download_url, is_local in self.get_versions():
            if version == requested_version:
                local_path = self._get_local_path(version)
                if not is_local:
                    self._download_and_extract_package(download_url, local_path)
                return local_path
