import os
import shutil
import tempfile
from zentral.utils.osx_package import PackageBuilder


class DummyPackageBuilder(PackageBuilder):
    package_name = "test123"
    base_package_identifier = "io.zentral.test123"

    def __init__(self):
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
        # Scripts
        os.mkdir(os.path.join(self.build_tmpl_dir, "scripts"))
        # root
        os.mkdir(os.path.join(self.build_tmpl_dir, "root"))
        super().__init__(None)

    def cleanup(self):
        shutil.rmtree(self.build_tmpl_dir)


def build_dummy_package():
    builder = DummyPackageBuilder()
    _, _, content = builder.build()
    builder.cleanup()
    return content
