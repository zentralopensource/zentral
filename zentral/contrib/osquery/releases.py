import os
from dateutil import parser
import requests
import shutil
import tempfile
from zentral.utils.local_dir import get_and_create_local_dir


class Releases(object):
    GITHUB_API_URL = "https://api.github.com/repos/facebook/osquery/releases"
    S3_BUCKET = "https://osquery-packages.s3.amazonaws.com/darwin/"

    def __init__(self):
        self.release_dir = None

    def _get_release_version(self, release):
        return release["name"]

    def _get_release_filename(self, release):
        return "osquery-{}.pkg".format(release["name"])

    def _get_local_path(self, filename):
        if not self.release_dir:
            self.release_dir = get_and_create_local_dir("osquery", "releases")
        return os.path.join(self.release_dir, filename)

    def _download_package(self, filename, local_path):
        download_url = "{}{}".format(self.S3_BUCKET, filename)
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
                filename = self._get_release_filename(release)
            except ValueError:
                continue
            version = self._get_release_version(release)
            created_at = parser.parse(release["created_at"])
            is_local = os.path.exists(self._get_local_path(filename))
            yield filename, version, created_at, is_local

    def get_requested_package(self, requested_filename):
        local_path = self._get_local_path(requested_filename)
        if not os.path.exists(local_path):
            self._download_package(requested_filename, local_path)
        return local_path
