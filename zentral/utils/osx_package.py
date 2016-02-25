from itertools import chain
import os
import shutil
from subprocess import check_call
import tempfile
from django.http import HttpResponse


class PackageBuilder(object):
    package_name = None
    build_tmpl_dir = None

    def __init__(self):
        # build template dir
        build_tmpl_dir = self.get_build_tmpl_dir()
        if not os.path.isdir(build_tmpl_dir):
            raise ValueError("build tmpl dir is not a dir")
        self.build_tmpl_dir = build_tmpl_dir
        # package name
        package_name = self.get_package_name()
        if not isinstance(package_name, str):
            raise TypeError("package name must be a str")
        if not package_name:
            raise ValueError("package name is an empty")
        if not package_name.endswith(".pkg"):
            package_name = "{}.pkg".format(package_name)
        self.package_name = package_name

    #
    # common build steps
    #

    def _prepare_temporary_build_dir(self):
        self.tempdir = tempfile.mkdtemp(suffix=self.__module__)
        self.builddir = os.path.join(self.tempdir, "build")
        shutil.copytree(self.build_tmpl_dir, self.builddir)

    def _prepare_package_info(self, package_identifier):
        number_of_files = install_bytes = 0
        for root, dirs, files in os.walk(self.get_root_path()):
            for name in chain(dirs, files):
                number_of_files += 1
                install_bytes += os.path.getsize(os.path.join(root, name))
        number_of_files = str(number_of_files)
        install_kbytes = str(install_bytes // 1024)
        self.replace_in_file(self.get_build_path("base.pkg", "PackageInfo"),
                             (("%NUMBER_OF_FILES%", number_of_files),
                              ("%INSTALL_KBYTES%", install_kbytes),
                              ("%PKG_IDENTIFIER%", package_identifier),))

    def _build_gziped_cpio_arch(self, dirname, arch_name):
        input_path = self.get_build_path(dirname)
        output_path = self.get_build_path("base.pkg", arch_name)
        check_call('(cd "{}" && find . | '
                   'cpio -o --quiet --format odc --owner 0:80 | '
                   'gzip -c) > "{}"'.format(input_path, output_path), shell=True)

    def _build_payload(self):
        self._build_gziped_cpio_arch("root", "Payload")

    def _build_scripts(self):
        self._build_gziped_cpio_arch("scripts", "Scripts")

    def _build_bom(self):
        check_call(["/usr/bin/mkbom", "-u", "0", "-g", "80",
                    self.get_root_path(),
                    self.get_build_path("base.pkg", "Bom")])

    def _build_pkg(self):
        pkg_path = os.path.join(self.tempdir, self.package_name)
        check_call('cd "{}" && '
                   '/usr/local/bin/xar '
                   '--compression none -cf "{}" *'.format(self.get_build_path("base.pkg"),
                                                          pkg_path),
                   shell=True)
        return pkg_path

    def _clean(self):
        shutil.rmtree(self.tempdir)

    #
    # API
    #

    # default settings

    def get_package_name(self):
        return self.package_name

    def get_build_tmpl_dir(self):
        return self.build_tmpl_dir

    # build

    def extra_build_steps(self, *args, **kwargs):
        pass

    def get_package_identifier(self, business_unit):
        package_identifier = self.package_identifier
        if business_unit:
            package_identifier = "{}.bu_{}".format(package_identifier,
                                                   business_unit.get_short_key())
        return package_identifier

    def build(self, business_unit, *args, **kwargs):
        self._prepare_temporary_build_dir()
        self.extra_build_steps(*args, **kwargs)
        self._prepare_package_info(self.get_package_identifier(business_unit))
        self._build_payload()
        self._build_scripts()
        self._build_bom()
        # TODO: memory
        with open(self._build_pkg(), 'rb') as f:
            content = f.read()
        self._clean()
        return content

    def build_and_make_response(self, *args, **kwargs):
        content = self.build(*args, **kwargs)
        # TODO: memory
        response = HttpResponse(content, "application/octet-stream")
        response['Content-Length'] = len(content)
        response['Content-Disposition'] = 'attachment; filename="{}"'.format(self.package_name)
        return response

    # build tools

    def get_build_path(self, *args):
        return os.path.join(self.builddir, *args)

    def get_root_path(self, *args):
        return self.get_build_path("root", *args)

    def replace_in_file(self, filename, patterns):
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        for pattern, replacement in patterns:
            content = content.replace(pattern, replacement)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
