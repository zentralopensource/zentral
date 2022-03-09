from django.core.management.base import BaseCommand
from zentral.contrib.monolith.models import ManifestEnrollmentPackage
from zentral.contrib.monolith.utils import build_manifest_enrollment_package


class Command(BaseCommand):
    help = 'Rebuild monolith manifest enrollment packages.'

    def handle(self, *args, **kwargs):
        manifests = set([])
        for mep in ManifestEnrollmentPackage.objects.all():
            build_manifest_enrollment_package(mep)
            manifests.add(mep.manifest)
            try:
                p = mep.file.path
            except NotImplementedError:
                p = mep.file.name
            print(p, "rebuilt")
        for manifest in manifests:
            old_version = manifest.version
            manifest.bump_version()
            manifest.refresh_from_db()
            print("Bump manifest", manifest.name, "version", old_version, "→", manifest.version)
