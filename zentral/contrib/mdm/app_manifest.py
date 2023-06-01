from hashlib import md5
import logging
import os
import plistlib
import subprocess
import tempfile
import zipfile
from defusedxml.ElementTree import fromstring, ParseError
from .models import Platform


logger = logging.getLogger("zentral.contrib.mdm.app_manifest")


MD5_SIZE = 10 * 2**20  # 10MB


def ensure_tmp_file(uploaded_file):
    if hasattr(uploaded_file, "temporary_file_path"):
        return uploaded_file.temporary_file_path(), False
    tmp_fd, tmp_filepath = tempfile.mkstemp()
    tmp_f = os.fdopen(tmp_fd, "wb")
    for chunk in uploaded_file.chunks():
        tmp_f.write(chunk)
    tmp_f.close()
    return tmp_filepath, True


def read_distribution_info(tmp_filepath):
    try:
        cp = subprocess.run(["xar", "-f", tmp_filepath, "-x", "--to-stdout", "Distribution"],
                            check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise ValueError("Could not read Distribution file")
    try:
        installer_script_elm = fromstring(cp.stdout)
    except ParseError:
        raise ValueError("Invalid Distribution file")
    title_elm = installer_script_elm.find("title")
    if title_elm:
        title = title_elm.text or ""
    else:
        title = None
    product_elm = installer_script_elm.find("product")
    if product_elm is None:
        logger.warning("Could not find <product/>")
        for pkg_ref in installer_script_elm.findall("pkg-ref"):
            try:
                product_id = pkg_ref.attrib["id"]
                product_version = pkg_ref.attrib["version"]
            except KeyError:
                continue
            else:
                if not product_id or not product_version:
                    continue
                else:
                    break
        else:
            raise ValueError("Could not find values for product_id and product_name")
    else:
        try:
            product_id = product_elm.attrib["id"]
            product_version = product_elm.attrib["version"]
        except KeyError as e:
            raise ValueError(f"Missing <product/> attr: {e.args[0]}")
    if not product_id:
        raise ValueError("Product ID is null")
    if not product_version:
        raise ValueError("Production version is null")
    bundles = []
    for bundle in installer_script_elm.findall(".//bundle"):
        try:
            bundles.append({k: bundle.attrib[v]
                            for k, v in (("version_str", "CFBundleShortVersionString"),
                                         ("version", "CFBundleVersion"),
                                         ("id", "id"),
                                         ("path", "path"))})
        except KeyError as e:
            logger.error(f"Missing <bundle/> attr: {e.args[0]}")
    return title, product_id, product_version, bundles, None, [Platform.MACOS]


def read_ipa_info(tmp_filepath):
    try:
        zf = zipfile.ZipFile(tmp_filepath)
    except zipfile.BadZipFile:
        raise ValueError("Could not read IPA file")
    info_plist_path = None
    for info in zf.infolist():
        if info.filename.endswith("Info.plist"):
            info_plist_path = info.filename
            break
    if not info_plist_path:
        raise ValueError("Could not find Info.plist")
    with zf.open(info_plist_path) as f:
        try:
            info_plist = plistlib.load(f)
        except Exception:
            raise ValueError("Could not load Info.plist")
    try:
        title = info_plist["CFBundleExecutable"]
        product_id = info_plist["CFBundleIdentifier"]
        product_version = info_plist["CFBundleShortVersionString"]
        bundles = [{
            "version_str": info_plist["CFBundleShortVersionString"],
            "version": info_plist["CFBundleVersion"],
            "id": info_plist["CFBundleIdentifier"],
        }]
        metadata = {
            "bundle-identifier": info_plist["CFBundleIdentifier"],
            "bundle-version": info_plist["CFBundleShortVersionString"],
            "kind": "software",
            "platform-identifier": f"com.apple.platform.{info_plist['DTPlatformName']}",
            "title": info_plist["CFBundleExecutable"],
        }
    except KeyError as e:
        raise ValueError(f"Missing key {e.args[0]} in Info.plist")
    # https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW11  # NOQA
    platforms = []
    device_families = info_plist.get("UIDeviceFamily")
    if not device_families:
        raise ValueError("Missing UIDeviceFamily")
    if not isinstance(device_families, list):
        device_families = [device_families]
    if 1 in device_families:
        platforms.append(Platform.IOS)
    if 2 in device_families:
        platforms.append(Platform.IPADOS)
    if 3 in device_families:
        platforms.append(Platform.TVOS)
    return title, product_id, product_version, bundles, metadata, platforms


def get_md5s(package_file, md5_size=MD5_SIZE):
    file_chunk_size = 64 * 2**10  # 64KB
    md5_size = (md5_size // file_chunk_size) * file_chunk_size
    md5s = []
    h = md5()
    current_size = 0
    for chunk in package_file.chunks(chunk_size=file_chunk_size):
        h.update(chunk)
        current_size += len(chunk)
        if current_size == md5_size:
            md5s.append(h.hexdigest())
            h = md5()
            current_size = 0
    if current_size:
        md5s.append(h.hexdigest())
        if len(md5s) == 1:
            md5_size = current_size
    return md5_size, md5s


def build_enterprise_app_manifest(package_file):
    # see https://support.apple.com/lt-lt/guide/deployment/dep873c25ac4/web
    _, ext = os.path.splitext(package_file.name)
    if ext == ".pkg":
        file_opener = read_distribution_info
    elif ext == ".ipa":
        file_opener = read_ipa_info
    else:
        raise ValueError(f"Unsupported file extension: {ext}")
    tmp_filepath, cleanup_tmp_file = ensure_tmp_file(package_file)
    try:
        title, product_id, product_version, bundles, metadata, platforms = file_opener(tmp_filepath)
    finally:
        if cleanup_tmp_file:
            os.unlink(tmp_filepath)
    md5_size, md5s = get_md5s(package_file)
    manifest = {"items": [{"assets": [{"kind": "software-package", "md5-size": md5_size, "md5s": md5s}]}]}
    if metadata:
        manifest["items"][0]["metadata"] = metadata
    return title, product_id, product_version, manifest, bundles, platforms
