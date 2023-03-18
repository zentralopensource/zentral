import hashlib
import os
import shutil
import subprocess
import tempfile
from urllib.parse import unquote
import xml.etree.ElementTree as ET
from .exceptions import AttachmentError


class AttachmentFile:
    def save_tempory_file(self):
        infile_fd, self.infile = tempfile.mkstemp()
        infile_f = os.fdopen(infile_fd, "wb")
        self.size = 0
        h = hashlib.sha256()
        for chunk in self.uploaded_file.chunks():
            infile_f.write(chunk)
            self.size += len(chunk)
            h.update(chunk)
        infile_f.close()
        self.hash = h.hexdigest()


class PackageFile(AttachmentFile):
    def get_package_xml_file_root(self, filename, tag_name):
        try:
            subprocess.check_call(["/usr/local/bin/xar", "-x",
                                   "-C", self.tmpdir, "-f", self.infile, filename])
        except subprocess.CalledProcessError:
            return
        filepath = os.path.join(self.tmpdir, filename)
        if not os.path.exists(filepath):
            return
        with open(filepath, "rb") as f:
            root = ET.parse(f).getroot()
            if root and root.tag == tag_name:
                return root

    @staticmethod
    def item_from_pkg_info(pkg_info):
        item = {"installed_size": 0}
        for pkg_info_attr, item_attr in (("identifier", "packageid"),
                                         ("version", "version")):
            try:
                val = pkg_info.attrib[pkg_info_attr]
            except KeyError:
                raise AttachmentError("PackageInfo w/o {}".format(pkg_info_attr))
            else:
                if not val:
                    raise AttachmentError(f"PackageInfo {pkg_info_attr} empty")
                item[item_attr] = val
        for payload in pkg_info.findall("payload"):
            try:
                item["installed_size"] += int(payload.attrib["installKBytes"])
            except KeyError:
                raise AttachmentError("pkg-info > payload w/o installKBytes")
        return item

    def iter_component_package_items(self):
        pkg_info = self.get_package_xml_file_root("PackageInfo", "pkg-info")
        if pkg_info:
            yield self.item_from_pkg_info(pkg_info)

    def iter_product_archive_items(self):
        installer_script = self.get_package_xml_file_root("Distribution",
                                                          "installer-gui-script")
        if not installer_script:
            return
        for pkg_ref in installer_script.findall("pkg-ref"):
            if not pkg_ref.text or not pkg_ref.text.strip():
                continue
            product_subdir = unquote(pkg_ref.text.strip().strip("#"))
            pkg_info = self.get_package_xml_file_root(
                os.path.join(product_subdir, "PackageInfo"),
                "pkg-info")
            if not pkg_info:
                raise AttachmentError("Missing PkgInfo for product {}".format(
                                          product_subdir
                                      ))
            yield self.item_from_pkg_info(pkg_info)

    def __init__(self, uploaded_file):
        self.uploaded_file = uploaded_file
        self.save_tempory_file()
        self.tmpdir = tempfile.mkdtemp()
        self.receipts = []
        try:
            for receipt_iterator in (self.iter_component_package_items,
                                     self.iter_product_archive_items):
                self.receipts.extend(receipt_iterator())
                if self.receipts:
                    break
            else:
                raise AttachmentError("Not a component package or a product archive")
        finally:
            os.remove(self.infile)
            shutil.rmtree(self.tmpdir)

    def get_pkginfo_data(self):
        return {
            'autoremove': False,
            'installed_size': sum(r['installed_size'] for r in self.receipts),
            'installer_item_hash': self.hash,
            'installer_item_size': self.size // 2**10,
            'minimum_os_version': '10.11.0',  # TODO: hardcoded
            'receipts': self.receipts,
            'unattended_install': True,
            'unattended_uninstall': True,
            'uninstall_method': 'removepackages',
            'uninstallable': True,
            'version': self.receipts[0]['version']
        }
