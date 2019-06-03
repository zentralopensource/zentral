import os
from dateutil import parser
import requests
import tarfile
from zentral.utils.local_dir import get_and_create_local_dir


class Releases(object):
    GITHUB_API_URL = "https://api.github.com/repos/elastic/beats/releases"
    FILENAME_TMPL = "filebeat-{version}-darwin-x86_64.tar.gz"
    DOWNLOAD_URL_TMPL = "https://artifacts.elastic.co/downloads/beats/filebeat/{filename}"

    def __init__(self):
        self.release_dir = None

    def _get_local_path(self, filename):
        if not self.release_dir:
            self.release_dir = get_and_create_local_dir("filebeat", "releases")
        dir_path = os.path.abspath(os.path.join(self.release_dir, filename.rsplit(".", 2)[0]))
        if not os.path.commonpath([self.release_dir, dir_path]) == self.release_dir:
            raise ValueError("wrong filename")
        if not os.path.exists(dir_path):
            os.mkdir(dir_path)
        return os.path.join(dir_path, "filebeat")

    def _download_and_extract_package(self, download_url, local_path):
        resp = requests.get(download_url, stream=True)
        _, ext = os.path.splitext(download_url)
        ext = ext.lstrip(".")
        if ext not in ("gz", "bz2", "xz"):
            ext = "*"
        tf = tarfile.open(fileobj=resp.raw, mode="r:{}".format(ext))
        tf.extractall(path=self.release_dir)

    def get_versions(self):
        resp = requests.get(self.GITHUB_API_URL)
        versions = []
        for release in resp.json():
            version = release["tag_name"].strip("v")
            filename = self.FILENAME_TMPL.format(version=version)
            download_url = self.DOWNLOAD_URL_TMPL.format(filename=filename)
            created_at = parser.parse(release["created_at"])
            is_local = os.path.exists(self._get_local_path(filename))
            versions.append((filename, version, created_at, download_url, is_local))
        versions.sort(key=lambda t: [int(i) for i in t[1].split("-")[0].split(".")], reverse=True)
        return versions

    def get_requested_package(self, requested_filename):
        local_path = self._get_local_path(requested_filename)
        if not os.path.exists(local_path):
            download_url = self.DOWNLOAD_URL_TMPL.format(filename=requested_filename)
            self._download_and_extract_package(download_url, local_path)
        return local_path
