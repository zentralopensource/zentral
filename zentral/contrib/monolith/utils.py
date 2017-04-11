import hashlib
import logging
from django.core.files.base import ContentFile

logger = logging.getLogger('zentral.contrib.monolith.utils')


# special munki catalogs and packages for zentral enrollment


def make_package_info(builder, manifest_enrollment_package, package_content):
    h = hashlib.sha256(package_content)
    installer_item_hash = h.hexdigest()
    installer_item_size = len(package_content)
    installed_size = installer_item_size * 10  # TODO: bug
    postinstall_script = """#!/usr/bin/python
import os

RECEIPTS_DIR = "/var/db/receipts/"

for filename in os.listdir(RECEIPTS_DIR):
    if filename.startswith("%s") and not filename.startswith("%s"):
        os.unlink(os.path.join(RECEIPTS_DIR, filename))
""" % (builder.base_package_identifier, builder.package_identifier)
    return {'autoremove': True,
            'description': '{} package'.format(builder.name),
            'display_name': builder.name,
            'installed_size': installed_size,
            'installer_item_hash': installer_item_hash,
            'installer_item_size': installer_item_size,
            'minimum_os_version': '10.9.0',  # TODO: hardcoded
            'name': manifest_enrollment_package.get_name(),
            'postinstall_script': postinstall_script,
            'receipts': [
                {'installed_size': installed_size,
                 'packageid': builder.package_identifier,
                 'version': builder.package_version},
            ],
            'unattended_install': True,
            'unattended_uninstall': True,
            'uninstallable': True,
            'uninstall_method': 'removepackages',
            'update_for': [manifest_enrollment_package.get_update_for()],
            'version': builder.package_version}


def build_manifest_enrollment_package(mep):
    mbu = mep.manifest.meta_business_unit
    bu = mbu.api_enrollment_business_units()[0]
    build_kwargs = mep.build_kwargs.copy()
    build_kwargs["version"] = "{}.0".format(mep.version)
    builder = mep.builder_class(bu, package_identifier_suffix="pk_{}".format(mep.id), **build_kwargs)
    _, package_content = builder.build()
    mep.pkg_info = make_package_info(builder, mep, package_content)
    mep.file.delete(False)
    mep.file.save(mep.get_installer_item_filename(),
                  ContentFile(package_content),
                  save=True)
