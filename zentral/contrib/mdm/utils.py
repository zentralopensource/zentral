from hashlib import md5
import logging
from django.core.files.base import ContentFile


logger = logging.getLogger("zentral.contrib.mdm.utils")


MD5_SIZE = 10 * 2**20  # 10MB


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


def build_manifest(title, package_file, pkg_refs):
    md5_size, md5s = get_md5s(package_file)
    asset = {"kind": "software-package",
             "md5-size": md5_size,
             "md5s": md5s}
    metadata = {"kind": "software", "title": title, "sizeInBytes": package_file.size}
    # we will add the url dynamically
    bundles = [{"bundle-identifier": pkg_ref["id"],
                "bundle-version": pkg_ref["version"]}
               for pkg_ref in pkg_refs]
    metadata.update(bundles.pop(0))
    if bundles:
        metadata["items"] = bundles
    return {"items": [{"assets": [asset], "metadata": metadata}]}


def build_mdm_enrollment_package(mep):
    builder = mep.get_builder_class()(mep.get_enrollment(), version=mep.version)
    _, pkg_refs, package_content = builder.build()
    package_file = ContentFile(package_content)
    mep.manifest = build_manifest(builder.name, package_file, pkg_refs)
    mep.file.delete(False)
    mep.file.save(mep.get_enrollment_package_filename(), package_file, save=True)
