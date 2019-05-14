from zentral.conf import settings


class Releases(object):
    def __init__(self, platform):
        self.platform = platform

    def get_versions(self):
        versions = []
        for version, binaries in settings["apps"]["zentral.contrib.filebeat"].get("scepclient", {}).items():
            binary = binaries.get(self.platform)
            if binary:
                versions.append((binary, version))
        return versions

    def get_requested_version(self, version):
        for binary, binary_version in self.get_versions():
            if binary_version == version:
                return binary

    def get_a_version(self):
        for binary, binary_version in self.get_versions():
            return binary
