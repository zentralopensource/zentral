import logging
import os
import shutil
import tempfile
import requests
from urllib.parse import urlparse
from requests.exceptions import ConnectionError, HTTPError
from zentral.utils.local_dir import get_and_create_local_dir


logger = logging.getLogger("zentral.contrib.osquery.releases")


GITHUB_API_URL = "https://api.github.com/repos/osquery/osquery/releases"


SUFFIXES = (
    ".linux.aarch64.rpm",
    ".linux_amd64.deb",
    ".linux_arm64.deb",
    ".linux.x86_64.rpm",
    ".msi",
    ".pkg"
)


def get_osquery_versions(ignore_draft_release=True, check_urls=True, last=3):
    try:
        resp = requests.get(GITHUB_API_URL, timeout=2)
        resp.raise_for_status()
    except (ConnectionError, HTTPError):
        logger.exception("Could not get versions from Github.")
        return
    versions = []
    releases = resp.json()
    if last:
        # limit releases to check
        releases = releases[:last * 2]
    for release in releases:
        if release.get("draft") and ignore_draft_release:
            continue
        prerelease = release.get("prerelease", False)
        tag_name = release["tag_name"]
        available_assets = {}
        for asset in release.get("assets", []):
            asset_name = asset.get("name")
            if not asset_name:
                continue
            if "dbgsym" in asset_name or "debuginfo" in asset_name:
                continue
            asset_suffix = None
            for suffix in SUFFIXES:
                if asset_name.endswith(suffix):
                    asset_suffix = suffix
                    break
            else:
                continue
            download_url = asset.get("browser_download_url")
            if not download_url:
                continue
            if check_urls:
                try:
                    resp = requests.head(download_url, allow_redirects=True, timeout=2)
                    resp.raise_for_status()
                except Exception:
                    logger.exception("Asset link %s broken", download_url)
                    continue
            available_assets[asset_suffix] = download_url
        if available_assets:
            versions.append((tag_name, prerelease, available_assets))
            if last and len(versions) >= last:
                break
    versions.sort(key=lambda t: [int(i) for i in t[0].split(".")], reverse=True)
    return versions


def get_osquery_local_asset(version, suffix):
    asset_name = download_url = None
    for release_version, prerelease, available_assets in get_osquery_versions(check_urls=False, last=0):
        if version == release_version:
            try:
                download_url = available_assets[suffix]
            except KeyError:
                raise ValueError("Could not find requested asset")
    asset_name = os.path.basename(urlparse(download_url).path)
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
