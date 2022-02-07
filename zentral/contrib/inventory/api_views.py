from django.db import connection
from django.urls import reverse
from django.utils import timezone
from django_filters import rest_framework as filters
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .forms import MacOSAppSearchForm
from .models import CurrentMachineSnapshot, MachineSnapshot, MachineTag, MetaBusinessUnit, Tag, Taxonomy
from .serializers import (MachineSerialNumbersSerializer,
                          MachineTagsUpdateSerializer,
                          MetaBusinessUnitSerializer,
                          TagSerializer)
from .tasks import (export_inventory, export_macos_apps,
                    export_machine_macos_app_instances,
                    export_machine_android_apps,
                    export_machine_deb_packages,
                    export_machine_ios_apps,
                    export_machine_program_instances,
                    export_machine_snapshots)
from .utils import MSQuery


# Machine mass tagging


class UpdateMachineTags(APIView):
    permission_required = ("inventory.add_tag", "inventory.add_taxonomy",
                           "inventory.add_machinetag", "inventory.delete_machinetag")
    permission_classes = [DjangoPermissionRequired]

    def _prepare_taxonomies_and_tags(self):
        self.tags_to_set = []
        self.taxonomies_to_clear = []
        for taxonomy_name, tag_name in self.data["tags"].items():
            if tag_name:
                taxonomy, _ = Taxonomy.objects.get_or_create(name=taxonomy_name)
                self.tags_to_set.append(Tag.objects.get_or_create(taxonomy=taxonomy, name=tag_name)[0])
            else:
                try:
                    self.taxonomies_to_clear.append(Taxonomy.objects.get(name=taxonomy_name))
                except Taxonomy.DoesNotExist:
                    pass

    def _iter_serial_numbers(self):
        args = []
        wheres = []
        principal_names = self.data["principal_users"].get("principal_names", [])
        if principal_names:
            args.append(tuple(principal_names))
            wheres.append("pu.principal_name IN %s")
        unique_ids = self.data["principal_users"].get("unique_ids", [])
        if unique_ids:
            args.append(tuple(unique_ids))
            wheres.append("pu.unique_id IN %s")
        query = (
            "select ms.serial_number "
            "from inventory_machinesnapshot as ms "
            "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id) "
            "join inventory_principaluser as pu on (pu.id = ms.principal_user_id) "
            "where {}"
        ).format(" or ".join(wheres))
        cursor = connection.cursor()
        cursor.execute(query, args)
        for t in cursor.fetchall():
            yield t[0]

    def _update_machine_tags(self, serial_number):
        total_removed = 0
        total_added = 0
        if self.taxonomies_to_clear:
            removed, _ = MachineTag.objects.filter(serial_number=serial_number,
                                                   tag__taxonomy__in=self.taxonomies_to_clear).delete()
            total_removed += removed
        for tag in self.tags_to_set:
            removed, _ = (MachineTag.objects.filter(serial_number=serial_number,
                                                    tag__taxonomy=tag.taxonomy)
                                            .exclude(tag__name=tag.name)).delete()
            total_removed += removed
            _, created = MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
            if created:
                total_added += 1
        return total_removed, total_added

    def post(self, request, *args, **kwargs):
        serializer = MachineTagsUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.data = serializer.data
        self._prepare_taxonomies_and_tags()
        found_machines = 0
        total_removed = 0
        total_added = 0
        for serial_number in self._iter_serial_numbers():
            found_machines += 1
            removed, added = self._update_machine_tags(serial_number)
            total_removed += removed
            total_added += added
        return Response({"machines": {"found": found_machines},
                         "tags": {"added": total_added,
                                  "removed": total_removed}})


# Archive or prune machines


class ArchiveMachines(APIView):
    permission_required = "inventory.change_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        serializer = MachineSerialNumbersSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        count, _ = CurrentMachineSnapshot.objects.filter(serial_number__in=serializer.data["serial_numbers"]).delete()
        return Response({"current_machine_snapshots": count})


class PruneMachines(APIView):
    permission_required = "inventory.delete_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        serializer = MachineSerialNumbersSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _, result = MachineSnapshot.objects.filter(serial_number__in=serializer.data["serial_numbers"]).delete()
        response = {}
        for model_name, response_attr in (("CurrentMachineSnapshot", "current_machine_snapshots"),
                                          ("MachineSnapshotCommit", "machine_snapshot_commits"),
                                          ("MachineSnapshot", "machine_snapshots")):
            response[response_attr] = result.get(f"inventory.{model_name}", 0)
        return Response(response)


# Machine and apps reports


class MachinesExport(APIView):
    permission_required = "inventory.view_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        export_format = request.GET.get("export_format", "xlsx")
        if export_format not in ("xlsx", "zip"):
            raise ValidationError("Unknown export format")
        msquery = MSQuery(request.GET)
        filename = "inventory_export_{:%Y-%m-%d_%H-%M-%S}.{}".format(timezone.now(), export_format)
        result = export_inventory.apply_async((msquery.get_urlencoded_canonical_query_dict(), filename))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MacOSAppsExport(APIView):
    permission_required = ("inventory.view_osxapp", "inventory.view_osxappinstance")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        export_format = request.data.pop("export_format", "xlsx")
        if export_format not in ("xlsx", "csv"):
            raise ValidationError("Invalid export format")
        form = MacOSAppSearchForm(request.data, export=True)
        if not form.is_valid():
            raise ValidationError("Invalid search parameters")
        filename = "macos_apps_export_{:%Y-%m-%d_%H-%M-%S}.{}".format(timezone.now(), export_format)
        result = export_macos_apps.apply_async((request.data, filename,))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


# Machine apps, debs and programs exports (ZIPPED CSV files)


class MachineAndroidAppsExport(APIView):
    permission_required = "inventory.view_androidapp"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_android_apps.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineDebPackagesExport(APIView):
    permission_required = "inventory.view_debpackage"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_deb_packages.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineIOSAppsExport(APIView):
    permission_required = "inventory.view_iosapp"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_ios_apps.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineMacOSAppInstancesExport(APIView):
    permission_required = ("inventory.view_osxapp", "inventory.view_osxappinstance")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_macos_app_instances.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineProgramInstancesExport(APIView):
    permission_required = ("inventory.view_program", "inventory.view_programinstance")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_program_instances.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineSnapshotsExport(APIView):
    permission_required = ("inventory.view_machinesnapshot",)
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_snapshots.apply_async(kwargs={"source_name": source_name})
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


# Standard DRF views


class MetaBusinessUnitList(generics.ListCreateAPIView):
    """
    List all MBUs, search MBU by name, or create a new MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = MetaBusinessUnitSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class MetaBusinessUnitDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = MetaBusinessUnitSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This meta business unit cannot be deleted')
        else:
            return super().perform_destroy(instance)


class TagList(generics.ListCreateAPIView):
    """
    List all tags, search tag by name, or create a new tag.
    """
    queryset = Tag.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = TagSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class TagDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a tag.
    """
    queryset = Tag.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = TagSerializer
