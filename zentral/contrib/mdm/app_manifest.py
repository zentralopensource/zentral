from hashlib import md5
import logging
import subprocess
from defusedxml.ElementTree import fromstring, ParseError


logger = logging.getLogger("zentral.contrib.mdm.app_manifest")


MD5_SIZE = 10 * 2**20  # 10MB


def read_distribution_info(package_file):
    try:
        cp = subprocess.run(["xar", "-f", package_file.temporary_file_path(), "-x", "--to-stdout", "Distribution"],
                            check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        raise ValueError("Could not read Distribution file")
    try:
        installer_script_elm = fromstring(cp.stdout)
    except ParseError:
        raise ValueError("Invalid Distribution file")
    title = installer_script_elm.find("title")
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
    return title, product_id, product_version, bundles


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
    # see https://support.apple.com/lt-lt/guide/deployment-reference-macos/ior5df10f73a/web
    title, product_id, product_version, bundles = read_distribution_info(package_file)
    md5_size, md5s = get_md5s(package_file)
    manifest = {"items": [{"assets": [{"kind": "software-package", "md5-size": md5_size, "md5s": md5s}]}]}
    return title, product_id, product_version, manifest, bundles
