import logging
from django.core.files.base import ContentFile


logger = logging.getLogger("zentral.contrib.mdm.utils")


def make_mep_manifest(builder, mep, package_content):
    # TODO: implement!
    return {}


def build_mdm_enrollment_package(mep):
    builder = mep.builder_class(mep.get_enrollment(), version=mep.version)
    _, package_content = builder.build()
    mep.manifest = make_mep_manifest(builder, mep, package_content)
    mep.file.delete(False)
    mep.file.save(mep.get_enrollment_package_filename(),
                  ContentFile(package_content),
                  save=True)
