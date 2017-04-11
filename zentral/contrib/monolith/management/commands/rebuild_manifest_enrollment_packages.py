from django.core.management.base import BaseCommand
from zentral.contrib.monolith.models import ManifestEnrollmentPackage
from zentral.contrib.monolith.utils import build_manifest_enrollment_package


class Command(BaseCommand):
    help = 'Rebuild monolith manifest enrollment packages.'

    def handle(self, *args, **kwargs):
        for mep in ManifestEnrollmentPackage.objects.all():
            build_manifest_enrollment_package(mep)
            print(mep.file.path, "rebuilt")
