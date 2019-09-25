import logging
import os
import shutil
import tempfile
import requests
from requests.exceptions import ConnectionError, HTTPError
from zentral.utils.local_dir import get_and_create_local_dir


logger = logging.getLogger("zentral.contrib.osquery.releases")


GITHUB_API_URL = "https://api.github.com/repos/facebook/osquery/releases"
ALTERNATIVE_PKG_DOWNLOAD_URL_TMPL = "https://pkg.osquery.io/darwin/osquery-{version}.pkg"

SUFFIXES = (".amd64.deb", ".msi", ".x86_64.rpm", ".pkg")


def get_osquery_versions(ignore_draft_release=True):
    try:
        resp = requests.get(GITHUB_API_URL)
        resp.raise_for_status()
    except (ConnectionError, HTTPError):
        logger.exception("Could not get versions from Github.")
        return
    versions = []
    for release in resp.json():
        if release.get("draft") and ignore_draft_release:
            continue
        prerelease = release.get("prerelease", False)
        available_assets = {}
        for asset in release.get("assets", []):
            asset_name = asset.get("name")
            for suffix in SUFFIXES:
                if asset_name.endswith(suffix):
                    browser_download_url = asset.get("browser_download_url")
                    if browser_download_url:
                        available_assets[suffix] = (asset_name, browser_download_url)
        if available_assets:
            versions.append((release["tag_name"], prerelease, available_assets))
    versions.sort(key=lambda t: [int(i) for i in t[0].split(".")], reverse=True)
    return versions


def get_osquery_local_asset(version, suffix):
    asset_name = download_url = None
    for release_version, prerelease, available_assets in get_osquery_versions():
        if version == release_version:
            try:
                asset_name, download_url = available_assets[suffix]
            except KeyError:
                pass
            break
    if asset_name is None and download_url is None and suffix == ".pkg":
        # try alternative download
        asset_name = "osquery-{version}.pkg".format(version=version)
        download_url = ALTERNATIVE_PKG_DOWNLOAD_URL_TMPL.format(version=version)
    if asset_name and download_url:
        release_dir = get_and_create_local_dir("osquery", "releases")
        local_asset_path = os.path.join(release_dir, asset_name)
        if not os.path.exists(local_asset_path):
            tmp_fh, tmp_path = tempfile.mkstemp(suffix=".osquery_asset{}".format(suffix))
            resp = requests.get(download_url, stream=True)
            resp.raise_for_status()
            with os.fdopen(tmp_fh, "wb") as f:
                for chunk in resp.iter_content(64 * 2**10):
                    f.write(chunk)
            shutil.move(tmp_path, local_asset_path)
        return local_asset_path
    else:
        raise ValueError("Could not find requested asset")
