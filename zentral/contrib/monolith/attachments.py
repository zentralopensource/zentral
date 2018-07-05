import hashlib
import os
import plistlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from .exceptions import AttachmentError


class AttachmentFile(object):
    type = None

    @staticmethod
    def save_tempory_file(f):
        infile_fd, infile = tempfile.mkstemp()
        infile_f = os.fdopen(infile_fd, "wb")
        size = 0
        for chunk in f.chunks():
            infile_f.write(chunk)
            size += len(chunk)
        infile_f.close()
        return infile, size

    def get_extra_pkginfo(self, sub_manifest_attachment):
        return {}

    def make_package_info(self, sub_manifest_attachment):
        name = sub_manifest_attachment.name
        h = hashlib.sha256()
        for chunk in sub_manifest_attachment.file.chunks():
            h.update(chunk)
        installer_item_hash = h.hexdigest()
        pkginfo = {'autoremove': False,
                   'description': "",
                   'display_name': name,
                   'installer_item_hash': installer_item_hash,
                   'unattended_install': True,
                   'unattended_uninstall': True,
                   'uninstallable': True,
                   'version': str(sub_manifest_attachment.version)}
        pkginfo.update(self.get_extra_pkginfo(sub_manifest_attachment))
        return pkginfo


class MobileconfigFile(AttachmentFile):
    type = "configuration_profile"

    def __init__(self, f):
        try:
            self._pl = plistlib.load(f)
        except plistlib.InvalidFileException:
            # maybe a signed plist
            infile, _ = self.save_tempory_file(f)
            outfile_fd, outfile = tempfile.mkstemp()
            outfile_f = os.fdopen(outfile_fd, "rb")
            try:
                # TODO: noverify -> verify signature ???
                subprocess.check_call(["/usr/bin/openssl", "smime", "-verify",
                                       "-in", infile, "-inform", "DER",
                                       "-noverify", "-out", outfile])
            except subprocess.CalledProcessError:
                # not a valid
                raise AttachmentError("Unable to read plist")
            else:
                try:
                    self._pl = plistlib.load(outfile_f)
                except plistlib.InvalidFileException:
                    raise AttachmentError("Signed data not a plist")
            finally:
                os.remove(infile)
                outfile_f.close()
                os.unlink(outfile)

        # extract attributes
        for attr, pl_attr in (("name", "PayloadDisplayName"),
                              ("identifier", "PayloadIdentifier")):
            try:
                setattr(self, attr, self._pl[pl_attr])
            except KeyError:
                raise AttachmentError("Plist without {}".format(pl_attr))

    def get_extra_pkginfo(self, sub_manifest_attachment):
        return {'installer_type': 'profile',
                'minimum_munki_version': '2.2',
                'minimum_os_version': '10.9.0',  # TODO: HARDCODED !!!
                'PayloadDisplayName': self.name,
                'PayloadIdentifier': self.identifier,
                'installer_item_size': 1,
                'uninstall_method': 'remove_profile'}


class PackageFile(AttachmentFile):
    type = "package"

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
                item[item_attr] = pkg_info.attrib[pkg_info_attr]
            except KeyError:
                raise AttachmentError("PackageInfo w/o {}".format(pkg_info_attr))
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
            product_subdir = pkg_ref.text.strip().strip("#")
            pkg_info = self.get_package_xml_file_root(
                os.path.join(product_subdir, "PackageInfo"),
                "pkg-info")
            if not pkg_info:
                raise AttachmentError("Missing PkgInfo for product {}".format(
                                          product_subdir
                                      ))
            yield self.item_from_pkg_info(pkg_info)

    def __init__(self, f):
        self.name = f.name
        self.infile, size = self.save_tempory_file(f)
        self.installer_item_size = size // 2**10
        self.tmpdir = tempfile.mkdtemp()
        self.items = []
        try:
            for item_iterator in (self.iter_component_package_items,
                                  self.iter_product_archive_items):
                self.items.extend(item_iterator())
                if self.items:
                    break
            else:
                raise AttachmentError("Not a component package or a product archive")
        finally:
            os.remove(self.infile)
            shutil.rmtree(self.tmpdir)
        self.installed_size = sum(i['installed_size'] for i in self.items)
        if len(self.items) == 1:
            item = self.items[0]
            self.identifier = item['packageid']
            self.version = item['version']
        else:
            # we will use the sub_manifest_attachment
            self.identifier = self.version = None

    def get_extra_pkginfo(self, sub_manifest_attachment):
        version = self.version or str(sub_manifest_attachment.version)
        identifier = self.identifier or self.name
        return {'identifier': identifier,
                'minimum_os_version': '10.5.0',  # TODO: HARDCODED !!!
                'installer_item_size': self.installer_item_size,
                'uninstall_method': 'removepackages',
                'installed_size': self.installed_size,
                'version': version,
                'receipts': self.items
                }
