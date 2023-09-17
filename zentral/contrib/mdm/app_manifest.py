from hashlib import md5, sha256
import logging
import os
import plistlib
import subprocess
import tempfile
from urllib.parse import urlparse
import zipfile
import boto3
from defusedxml.ElementTree import fromstring, ParseError
from django.core.files.uploadedfile import TemporaryUploadedFile, UploadedFile
from zentral.utils.aws import get_region as get_aws_region
from .models import Platform


logger = logging.getLogger("zentral.contrib.mdm.app_manifest")


MD5_SIZE = 10 * 2**20  # 10MB


def validate_configuration(configuration):
    if configuration:
        if configuration.startswith("<dict>"):
            # to make it easier for the users
            configuration = f'<plist version="1.0">{configuration}</plist>'
        try:
            loaded_configuration = plistlib.loads(configuration.encode("utf-8"))
        except Exception:
            raise ValueError("Invalid property list")
        if not isinstance(loaded_configuration, dict):
            raise ValueError("Not a dictionary")
        return plistlib.dumps(loaded_configuration)
    else:
        return None


def download_s3_package(parsed_package_uri, package_sha256):
    bucket = parsed_package_uri.netloc
    key = parsed_package_uri.path.lstrip("/")
    _, ext = os.path.splitext(key)
    if ext not in (".pkg", ".ipa"):
        raise ValueError(f"Unsupported file extension: '{ext}'")
    file = tempfile.NamedTemporaryFile(suffix=f".downloaded_s3_package{ext}", delete=False)
    try:
        s3_client = boto3.client('s3', region_name=get_aws_region())
        s3_client.download_fileobj(bucket, key, file)
    except Exception:
        file.close()
        os.unlink(file.name)
        raise
    return file


def download_package(package_uri, package_sha256):
    parsed_package_uri = urlparse(package_uri)
    if parsed_package_uri.scheme == "s3":
        file = download_s3_package(parsed_package_uri, package_sha256)
    else:
        raise ValueError(f"Unknown package URI scheme: '{parsed_package_uri.scheme}'")
    # verify hash
    file.seek(0)
    h = sha256()
    while True:
        chunk = file.read(2**10 * 64)
        if not chunk:
            break
        h.update(chunk)
    if h.hexdigest() != package_sha256:
        raise ValueError("Hash mismatch")
    file.seek(0)
    return os.path.basename(parsed_package_uri.path), file


def ensure_tmp_file(file):
    if isinstance(file, TemporaryUploadedFile):
        return file.temporary_file_path(), False
    elif isinstance(file, UploadedFile):
        tmp_fd, tmp_filepath = tempfile.mkstemp()
        tmp_f = os.fdopen(tmp_fd, "wb")
        while True:
            chunk = file.read(2**10 * 64)
            if not chunk:
                break
            tmp_f.write(chunk)
        tmp_f.close()
        return tmp_filepath, True
    elif hasattr(file, "name"):
        return file.name, False
    raise ValueError("Unsupported file type")


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
    # product ID product version
    product_id = product_version = None
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
    ea_data = {
        "product_id": product_id,
        "product_version": product_version,
        "bundles": [],
    }
    for bundle in installer_script_elm.findall(".//bundle"):
        try:
            ea_data["bundles"].append({k: bundle.attrib[v]
                                       for k, v in (("version_str", "CFBundleShortVersionString"),
                                                    ("version", "CFBundleVersion"),
                                                    ("id", "id"),
                                                    ("path", "path"))})
        except KeyError as e:
            logger.error(f"Missing <bundle/> attr: {e.args[0]}")
    # name
    name = product_id
    title_elm = installer_script_elm.find("title")
    if title_elm and title_elm.text:
        name = title_elm.text
    return name, [Platform.MACOS], ea_data


def read_ipa_info(tmp_filepath):
    try:
        zf = zipfile.ZipFile(tmp_filepath)
    except zipfile.BadZipFile:
        raise ValueError("Could not read IPA file")
    info_plist_path = None
    for zinfo in zf.infolist():
        if zinfo.filename.endswith("Info.plist"):
            info_plist_path = zinfo.filename
            break
    if not info_plist_path:
        raise ValueError("Could not find Info.plist")
    with zf.open(info_plist_path) as f:
        try:
            info_plist = plistlib.load(f)
        except Exception:
            raise ValueError("Could not load Info.plist")
    try:
        name = info_plist["CFBundleExecutable"]
        ea_data = {
            "product_id": info_plist["CFBundleIdentifier"],
            "product_version": info_plist["CFBundleShortVersionString"],
            "bundles": [{
                "version_str": info_plist["CFBundleShortVersionString"],
                "version": info_plist["CFBundleVersion"],
                "id": info_plist["CFBundleIdentifier"],
            }],
            "metadata": {
                "bundle-identifier": info_plist["CFBundleIdentifier"],
                "bundle-version": info_plist["CFBundleShortVersionString"],
                "kind": "software",
                "platform-identifier": f"com.apple.platform.{info_plist['DTPlatformName']}",
                "title": info_plist["CFBundleExecutable"],
            },
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
    return name, platforms, ea_data


def get_md5s(package_file, md5_size=MD5_SIZE, compute_sha256=False):
    file_chunk_size = 64 * 2**10  # 64KB
    md5_size = (md5_size // file_chunk_size) * file_chunk_size
    md5s = []
    h = md5()
    if compute_sha256:
        h2 = sha256()
    current_size = 0
    package_size = 0
    package_file.seek(0)
    while True:
        chunk = package_file.read(2**10 * 64)
        if not chunk:
            break
        h.update(chunk)
        if compute_sha256:
            h2.update(chunk)
        chunk_length = len(chunk)
        current_size += chunk_length
        package_size += chunk_length
        if current_size == md5_size:
            md5s.append(h.hexdigest())
            h = md5()
            current_size = 0
    if current_size:
        md5s.append(h.hexdigest())
        if len(md5s) == 1:
            md5_size = current_size
    return md5_size, md5s, package_size, h2.hexdigest() if compute_sha256 else None


def read_package_info(package_file, compute_sha256=False):
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
        name, platforms, ea_data = file_opener(tmp_filepath)
    finally:
        if cleanup_tmp_file:
            os.unlink(tmp_filepath)
    md5_size, md5s, package_size, package_sha256 = get_md5s(package_file, compute_sha256=compute_sha256)
    manifest = {"items": [{"assets": [{"kind": "software-package", "md5-size": md5_size, "md5s": md5s}]}]}
    metadata = ea_data.pop("metadata", None)
    if metadata:
        manifest["items"][0]["metadata"] = metadata
    ea_data["manifest"] = manifest
    ea_data["package_size"] = package_size
    if compute_sha256:
        ea_data["package_sha256"] = package_sha256
    return name, platforms, ea_data
