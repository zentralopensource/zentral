from itertools import chain
import os
import plistlib
import shutil
from subprocess import check_call
import tempfile

BUILD_TMPL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "build.tmpl")


class OsqueryZentralEnrollPkgBuilder(object):
    def __init__(self, tls_hostname, enroll_secret_secret, tls_server_certs=None):
        self.tls_hostname = tls_hostname
        self.enroll_secret_secret = enroll_secret_secret
        if tls_server_certs and not os.path.exists(tls_server_certs):
            raise ValueError("tls_server_certs file {} is not readable".format(tls_server_certs))
        self.tls_server_certs = tls_server_certs

    def copy_build_tmpl(self):
        self.tempdir = tempfile.mkdtemp(suffix="osquery_zentral_enrollment_pkg")
        self.builddir = os.path.join(self.tempdir, "build")
        shutil.copytree(BUILD_TMPL_DIR, self.builddir)
        self.launchd_plist = os.path.join(self.builddir, "root/Library/LaunchDaemons/com.facebook.osqueryd.plist")

    def _replace_in_file(self, filename, patterns):
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        for pattern, replacement in patterns:
            content = content.replace(pattern, replacement)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

    def set_tls_hostname(self):
        self._replace_in_file(self.launchd_plist,
                              (("%TLS_HOSTNAME%", self.tls_hostname),))

    def set_enroll_secret_secret(self):
        self._replace_in_file(os.path.join(self.builddir, "scripts/preinstall"),
                              (("%ENROLL_SECRET_SECRET%", self.enroll_secret_secret),))

    def include_tls_server_certs(self):
        # copy crt in build dir
        shutil.copy(self.tls_server_certs,
                    os.path.join(self.builddir, "root/usr/local/zentral/tls_server_certs.crt"))
        # add command line option
        with open(self.launchd_plist, "rb") as f:
            pl = plistlib.load(f)
        pl["ProgramArguments"].append("--tls_server_certs=/usr/local/zentral/tls_server_certs.crt")
        with open(self.launchd_plist, "wb") as f:
            plistlib.dump(pl, f)

    def set_number_of_files_and_install_kbytes(self):
        number_of_files = install_bytes = 0
        for root, dirs, files in os.walk(os.path.join(self.builddir, "root")):
            for name in chain(dirs, files):
                number_of_files += 1
                install_bytes += os.path.getsize(os.path.join(root, name))
        number_of_files = str(number_of_files)
        install_kbytes = str(install_bytes // 1024)
        self._replace_in_file(os.path.join(self.builddir, "base.pkg/PackageInfo"),
                              (("%NUMBER_OF_FILES%", number_of_files),
                               ("%INSTALL_KBYTES%", install_kbytes)))

    def _build_gziped_cpio_arch(self, dirname, arch_name):
        input_path = os.path.join(self.builddir, dirname)
        output_path = os.path.join(self.builddir, "base.pkg", arch_name)
        check_call('(cd "{}" && find . | cpio -o --quiet --format odc --owner 0:80 | gzip -c) > "{}"'.format(input_path, output_path), shell=True)

    def build_payload(self):
        self._build_gziped_cpio_arch(os.path.join(self.builddir, "root"), "Payload")

    def build_scripts(self):
        self._build_gziped_cpio_arch(os.path.join(self.builddir, "scripts"), "Scripts")

    def build_bom(self):
        check_call(["/usr/bin/mkbom", "-u", "0", "-g", "80", os.path.join(self.builddir, "root"), os.path.join(self.builddir, "base.pkg", "Bom")])

    def build_pkg(self):
        pkg_path = os.path.join(self.tempdir, "installer.pkg")
        check_call('cd "{}" && /usr/local/bin/xar --compression none -cf "{}" *'.format(os.path.join(self.builddir, "base.pkg"), pkg_path), shell=True)
        return pkg_path

    def clean(self):
        shutil.rmtree(self.tempdir)

    def build(self):
        self.copy_build_tmpl()
        self.set_tls_hostname()
        self.set_enroll_secret_secret()
        if self.tls_server_certs:
            self.include_tls_server_certs()
        self.set_number_of_files_and_install_kbytes()
        self.build_payload()
        self.build_scripts()
        self.build_bom()
        # TODO: memory
        with open(self.build_pkg(), 'rb') as f:
            content = f.read()
        self.clean()
        return "zentral_osquery_enroll.pkg", content, len(content)
