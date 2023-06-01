import os
import stat
import shutil
import tempfile
from django.utils.text import slugify
from zentral.utils.osx_package import PackageBuilder


class DummyPackageBuilder(PackageBuilder):
    def __init__(self, name, version, product_archive_title=None):
        self.package_name = name
        self.base_package_identifier = "io.zentral.{}".format(slugify(name))
        self.build_tmpl_dir = tempfile.mkdtemp()
        # package template dir
        base_pkg_path = os.path.join(self.build_tmpl_dir, "base.pkg")
        os.mkdir(base_pkg_path)
        # PackageInfo
        with open(os.path.join(base_pkg_path, "PackageInfo"), "w") as f:
            f.write(
                '<?xml version="1.0" encoding="utf-8" standalone="no"?>'
                '<pkg-info postinstall-action="none" format-version="2" identifier="%PKG_IDENTIFIER%"'
                ' version="%VERSION%" generator-version="Zentral 0.1" install-location="/" auth="root">'
                '<payload numberOfFiles="%NUMBER_OF_FILES%" installKBytes="%INSTALL_KBYTES%"/>'
                '<bundle-version/>'
                '<upgrade-bundle/>'
                '<update-bundle/>'
                '<atomic-update-bundle/>'
                '<strict-identifier/>'
                '<relocate/>'
                '</pkg-info>'
            )
        # scripts
        script_dir = os.path.join(self.build_tmpl_dir, "scripts")
        os.mkdir(script_dir)
        preinstall = os.path.join(script_dir, "preinstall")
        with open(preinstall, "w") as f:
            f.write("#!/bin/bash\nyes")
        f_stat = os.stat(preinstall)
        os.chmod(preinstall, f_stat.st_mode | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXOTH)
        postinstall = os.path.join(script_dir, "postinstall")
        with open(postinstall, "w") as f:
            f.write("#!/bin/bash\nyes")
        f_stat = os.stat(postinstall)
        os.chmod(postinstall, f_stat.st_mode | stat.S_IXUSR | stat.S_IWGRP | stat.S_IXOTH)
        # file
        ztl_dir = os.path.join(self.build_tmpl_dir, "root/usr/local/zentral")
        os.makedirs(ztl_dir)
        with open(os.path.join(ztl_dir, "dummy"), "w") as f:
            f.write(f"{name} v{version}")
        super().__init__(None, version=version)
        self.product_archive_title = product_archive_title

    def get_product_archive_title(self):
        return self.product_archive_title

    def cleanup(self):
        shutil.rmtree(self.build_tmpl_dir)


def build_dummy_package(name="test123", version="1.0", product_archive_title=None):
    builder = DummyPackageBuilder(name, version, product_archive_title)
    _, _, content = builder.build()
    builder.cleanup()
    return content
