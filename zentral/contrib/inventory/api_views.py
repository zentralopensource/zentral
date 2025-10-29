from django.db import connection, transaction
from django.http import Http404
from django.urls import reverse
from django.utils import timezone
from django_filters import rest_framework as filters
from rest_framework import generics, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.api_authentication import APITokenAuthentication
from zentral.core.events.base import EventRequest
from zentral.utils.drf import (DefaultDjangoModelPermissions, DjangoPermissionRequired,
                               ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit)
from .events import JMESPathCheckCreated, JMESPathCheckDeleted, JMESPathCheckUpdated
from .forms import AndroidAppSearchForm, DebPackageSearchForm, IOSAppSearchForm, MacOSAppSearchForm, ProgramsSearchForm
from .models import (CurrentMachineSnapshot,
                     JMESPathCheck,
                     MachineSnapshot,
                     MachineTag,
                     MetaBusinessUnit,
                     MetaMachine,
                     Tag, Taxonomy)
from .serializers import (CleanupInventorySerializer,
                          JMESPathCheckSerializer,
                          MachineSerialNumbersSerializer,
                          MachineTagsUpdateSerializer,
                          MetaBusinessUnitSerializer,
                          MetaMachineSerializer,
                          TagSerializer, TaxonomySerializer)
from .tasks import (cleanup_inventory,
                    export_inventory,
                    export_full_inventory,
                    export_android_apps, export_deb_packages, export_ios_apps, export_macos_apps, export_programs,
                    export_machine_macos_app_instances,
                    export_machine_android_apps,
                    export_machine_deb_packages,
                    export_machine_ios_apps,
                    export_machine_program_instances,
                    export_machine_snapshots)
from .utils import MSQuery, add_machine_tags, remove_machine_tags


# Machine mass tagging


class UpdateMachineTags(APIView):
    serializer_class = MachineTagsUpdateSerializer
    permission_required = ("inventory.add_tag", "inventory.add_taxonomy",
                           "inventory.add_machinetag", "inventory.delete_machinetag")
    permission_classes = [DjangoPermissionRequired]

    def _prepare_taxonomies_and_tags(self):
        self.tags_to_set = {}
        self.tags_to_add = []
        self.tags_to_remove = []
        self.taxonomies_to_clear = []
        for operation in self.data["operations"]:
            kind = operation["kind"]
            taxonomy_name = operation.get("taxonomy")
            names = operation["names"]
            taxonomy = None
            if taxonomy_name and (kind == "ADD" or (kind == "SET" and names)):
                taxonomy, _ = Taxonomy.objects.get_or_create(name=taxonomy_name)
            if kind == "SET":
                if names:
                    self.tags_to_set.setdefault(taxonomy, []).extend(
                        Tag.objects.get_or_create(taxonomy=taxonomy, name=name)[0]
                        for name in names
                    )
                else:
                    self.taxonomies_to_clear.append(taxonomy_name)
            elif kind == "ADD":
                self.tags_to_add.extend(
                    Tag.objects.get_or_create(name=name, defaults={"taxonomy": taxonomy})[0]
                    for name in names
                )
            elif kind == "REMOVE":
                self.tags_to_remove.extend(
                    Tag.objects.filter(name__in=names)
                )

    def _iter_serial_numbers(self):
        # serial numbers
        serial_numbers = self.data.get("serial_numbers")
        if serial_numbers:
            yield from serial_numbers
            return
        # principal users
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
            total_removed += remove_machine_tags(
                serial_number,
                [mt.tag
                 for mt in MachineTag.objects.select_related("tag")
                                             .filter(serial_number=serial_number,
                                                     tag__taxonomy__name__in=self.taxonomies_to_clear)],
                self.request,
            )
        for taxonomy, tags in self.tags_to_set.items():
            total_added += add_machine_tags(serial_number, tags, self.request)
            total_removed += remove_machine_tags(
                serial_number,
                [mt.tag
                 for mt in MachineTag.objects.select_related("tag")
                                             .filter(serial_number=serial_number,
                                                     tag__taxonomy=taxonomy)
                                             .exclude(tag__in=tags)],
                self.request,
            )
        total_added += add_machine_tags(serial_number, self.tags_to_add, self.request)
        total_removed += remove_machine_tags(serial_number, self.tags_to_remove, self.request)
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


# MetaMachine


class MetaMachineView(APIView):
    permission_required = "inventory.view_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def get(self, request, *args, **kwargs):
        mm = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        if not mm.snapshots:
            raise Http404
        serializer = MetaMachineSerializer(mm)
        return Response(serializer.data)


# Archive or prune machines


class ArchiveMachines(APIView):
    serializer_class = MachineSerialNumbersSerializer
    permission_required = "inventory.change_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        serializer = MachineSerialNumbersSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        count, _ = CurrentMachineSnapshot.objects.filter(serial_number__in=serializer.data["serial_numbers"]).delete()
        return Response({"current_machine_snapshots": count})


class PruneMachines(APIView):
    serializer_class = MachineSerialNumbersSerializer
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


# Machine and apps reports based on the UI views


class MachinesExport(APIView):
    serializer_class = None
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
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


class BaseAppsExport(APIView):
    serializer_class = None  # Uses form validation instead of serializer
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = None
    permission_classes = [DjangoPermissionRequired]
    form_class = None
    filename_prefix = None
    task = None

    def post(self, request, *args, **kwargs):
        export_format = request.data.pop("export_format", "xlsx")
        if export_format not in ("xlsx", "csv"):
            raise ValidationError("Invalid export format")
        form = self.form_class(request.data, export=True)
        if not form.is_valid():
            raise ValidationError("Invalid search parameters")
        filename = "{}_export_{:%Y-%m-%d_%H-%M-%S}.{}".format(self.filename_prefix, timezone.now(), export_format)
        result = self.task.apply_async((request.data, filename,))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class AndroidAppsExport(BaseAppsExport):
    permission_required = "inventory.view_androidapp"
    form_class = AndroidAppSearchForm
    filename_prefix = "android_apps"
    task = export_android_apps


class DebPackagesExport(BaseAppsExport):
    permission_required = "inventory.view_debpackage"
    form_class = DebPackageSearchForm
    filename_prefix = "deb_packages"
    task = export_deb_packages


class IOSAppsExport(BaseAppsExport):
    permission_required = "inventory.view_iosapp"
    form_class = IOSAppSearchForm
    filename_prefix = "ios_apps"
    task = export_ios_apps


class MacOSAppsExport(BaseAppsExport):
    permission_required = ("inventory.view_osxapp", "inventory.view_osxappinstance")
    form_class = MacOSAppSearchForm
    filename_prefix = "macos_apps"
    task = export_macos_apps


class ProgramsExport(BaseAppsExport):
    permission_required = ("inventory.view_program", "inventory.view_programinstance")
    form_class = ProgramsSearchForm
    filename_prefix = "programs"
    task = export_programs


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


# Cleanup


class CleanupInventory(APIView):
    """
    Start inventory cleanup task
    """
    serializer_class = CleanupInventorySerializer
    permission_required = ("inventory.delete_machinesnapshot",)
    permission_classes = [DjangoPermissionRequired]
    parser_classes = [FormParser, JSONParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = CleanupInventorySerializer(data=request.data)
        if serializer.is_valid():
            event_request = EventRequest.build_from_request(request)
            result = cleanup_inventory.apply_async((serializer.data["days"], event_request.serialize(),))
            return Response({"task_id": result.id,
                             "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                            status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Full export


class FullExport(APIView):
    serializer_class = None  # No request body
    permission_required = "inventory.view_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        result = export_full_inventory.apply_async()
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


# Standard DRF views


class JMESPathCheckFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="compliance_check__name")


class JMESPathCheckList(generics.ListCreateAPIView):
    """
    List, search by name or create JMESPath compliance checks.
    """
    queryset = JMESPathCheck.objects.select_related("compliance_check").all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = JMESPathCheckSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = JMESPathCheckFilter

    def perform_create(self, serializer):
        serializer.save()
        event = JMESPathCheckCreated.build_from_request_and_object(self.request, serializer.instance)
        transaction.on_commit(lambda: event.post())


class JMESPathCheckDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a JMESPath compliance check.
    """
    queryset = JMESPathCheck.objects.select_related("compliance_check").all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = JMESPathCheckSerializer

    def perform_update(self, serializer):
        serializer.save()
        event = JMESPathCheckUpdated.build_from_request_and_object(self.request, serializer.instance)
        transaction.on_commit(lambda: event.post())

    def perform_destroy(self, instance):
        event = JMESPathCheckDeleted.build_from_request_and_object(self.request, instance)
        instance.compliance_check.delete()
        transaction.on_commit(lambda: event.post())


class MetaBusinessUnitList(ListCreateAPIViewWithAudit):
    """
    List all MBUs, search MBU by name, or create a new MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    serializer_class = MetaBusinessUnitSerializer
    filterset_fields = ('name',)


class MetaBusinessUnitDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    serializer_class = MetaBusinessUnitSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This meta business unit cannot be deleted')
        else:
            return super().perform_destroy(instance)


class TagList(ListCreateAPIViewWithAudit):
    """
    List all tags, search tag by name, or create a new tag.
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    filterset_fields = ('name',)


class TagDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a tag.
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer


class TaxonomyList(ListCreateAPIViewWithAudit):
    """
    List all taxonomies, search by taxonomy name, or create a new taxonomy.
    """
    queryset = Taxonomy.objects.all()
    serializer_class = TaxonomySerializer
    filterset_fields = ('name',)


class TaxonomyDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a taxonomy.
    """
    queryset = Taxonomy.objects.all()
    serializer_class = TaxonomySerializer
