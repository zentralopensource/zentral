from django.core.management.base import BaseCommand, CommandError
from django.db.models import F
from zentral.contrib.monolith.models import Manifest, ManifestEnrollmentPackage
from zentral.contrib.monolith.utils import build_manifest_enrollment_package


class Command(BaseCommand):
    help = 'Rebuild monolith manifest enrollment packages.'

    def add_arguments(self, parser):
        parser.add_argument("--manifest", type=int, nargs="+", metavar="ID",
                            help="only rebuild the enrollment packages of these manifests")
        parser.add_argument("--new-version", action="store_true",
                            help="increase the version of the enrollment packages, to give them a new filename. "
                                 "the enrollment versions do not change, so the machines that are up to date do "
                                 "not install the packages again.")

    def write(self, msg):
        if self.verbosity:
            self.stdout.write(msg)

    def get_queryset(self, manifest_pks):
        qs = ManifestEnrollmentPackage.objects.select_related("manifest").all()
        if not manifest_pks:
            return qs
        manifest_pks = set(manifest_pks)
        known_pks = set(Manifest.objects.filter(pk__in=manifest_pks).values_list("pk", flat=True))
        unknown_pks = manifest_pks - known_pks
        if unknown_pks:
            raise CommandError("Unknown manifest: {}".format(", ".join(str(pk) for pk in sorted(unknown_pks))))
        qs = qs.filter(manifest__pk__in=manifest_pks)
        # a manifest with no enrollment package would rebuild nothing, with no error
        for pk in sorted(manifest_pks - set(qs.values_list("manifest__pk", flat=True))):
            self.stderr.write(f"Manifest {pk} has no enrollment package")
        return qs

    def handle(self, *args, **kwargs):
        self.verbosity = kwargs.get("verbosity", 1)
        new_version = kwargs.get("new_version", False)
        manifests = set([])
        for mep in self.get_queryset(kwargs.get("manifest")):
            if new_version:
                mep.version = F("version") + 1
                mep.save()
                mep.refresh_from_db()
            build_manifest_enrollment_package(mep)
            manifests.add(mep.manifest)
            try:
                p = mep.file.path
            except NotImplementedError:
                p = mep.file.name
            self.write(f"{p} rebuilt")
        for manifest in manifests:
            old_version = manifest.version
            manifest.bump_version()
            manifest.refresh_from_db()
            self.write(f"Bump manifest {manifest.name} version {old_version} → {manifest.version}")
