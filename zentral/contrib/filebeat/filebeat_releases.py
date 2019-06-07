import os
import requests
import tarfile
from zentral.utils.local_dir import get_and_create_local_dir


GITHUB_BEATS_RELEASES_URL = "https://api.github.com/repos/elastic/beats/releases"
FILEBEAT_RELEASE_NAME_TMPL = "filebeat-{version}-{platform}-x86_64"
FILEBEAT_DOWNLOAD_URL_TMPL = "https://artifacts.elastic.co/downloads/beats/filebeat/{release_name}.tar.gz"


def get_filebeat_versions():
    resp = requests.get(GITHUB_BEATS_RELEASES_URL)
    versions = []
    for release in resp.json():
        versions.append(release["tag_name"].strip("v"))
    versions.sort(key=lambda v: [int(i) for i in v.split("-")[0].split(".")], reverse=True)
    return versions


def get_filebeat_binary(version, platform="darwin"):
    version = version.strip(".\/")
    platform = platform.strip(".\/")
    # release dir
    releases_root = get_and_create_local_dir("filebeat", "releases")
    release_name = FILEBEAT_RELEASE_NAME_TMPL.format(version=version, platform=platform)

    # binary exists?
    release_dir = os.path.join(releases_root, release_name)
    filebeat_binary_path = os.path.join(release_dir, "filebeat")
    if not os.path.exists(filebeat_binary_path):
        # download release
        download_url = FILEBEAT_DOWNLOAD_URL_TMPL.format(release_name=release_name)
        resp = requests.get(download_url, stream=True)
        # extract release
        tf = tarfile.open(fileobj=resp.raw, mode="r:gz")
        tf.extractall(path=releases_root)

    return filebeat_binary_path
