import itertools
import logging
from django.db import IntegrityError, OperationalError, connection, transaction
from django.db.models import Q
from django.http import Http404
from django.urls import reverse
from django.utils import timezone
from django_filters import rest_framework as filters
from psycopg2.errors import DeadlockDetected
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.views import APIView
from accounts.api_authentication import APITokenAuthentication
from pbac.engine import engine
from pbac.entities import Principal, Request
from zentral.core.events.base import EventRequest
from zentral.utils.drf import (DjangoPermissionRequired, ListCreateAPIViewWithAudit,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from .forms import AndroidAppSearchForm, DebPackageSearchForm, IOSAppSearchForm, MacOSAppSearchForm, ProgramsSearchForm
from .models import (JMESPathCheck,
                     MachineSnapshot,
                     MetaBusinessUnit,
                     MetaMachine,
                     Tag, Taxonomy)
from .pbac import TagAnyMachineRequest, tag_any_machine_action
from .serializers import (CleanupInventorySerializer,
                          FullExportSerializer,
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
from .utils import MSQuery, add_machine_tags, archive_machine_snapshots, remove_machine_tags


logger = logging.getLogger("zentral.contrib.inventory.api_views")


# Machine mass tagging


class MachineTagsUpdatePermission(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        # A preview on all the tags, before the validation of the body. Its Deny is final. Its Allow only
        # means that some tag could be permitted: the post decides on each one.
        principal = Principal.from_user(request.user)
        if engine.undecided_policies(Request(principal, tag_any_machine_action, None)):
            return True
        logger.error("Permission denied %s %s on any resource", principal, tag_any_machine_action,
                     extra={"request": request})
        return False


class UpdateMachineTags(APIView):
    # no decision on the machines, see tagAnyMachine in .pbac
    permission_classes = [MachineTagsUpdatePermission]

    max_attempts = 3

    def _resolve_tags(self):
        operations = self.data["operations"]
        taxonomies = {taxonomy.name: taxonomy
                      for taxonomy in Taxonomy.objects.filter(
                          name__in={operation["taxonomy"] for operation in operations if operation["kind"] == "SET"}
                      )}
        names = set(itertools.chain.from_iterable(operation["names"] for operation in operations
                                                  if operation["kind"] != "SET"))
        tags = {}
        taxonomy_tags = {taxonomy: [] for taxonomy in taxonomies.values()}
        for tag in (Tag.objects.select_related("taxonomy")
                               .filter(Q(name__in=names) | Q(taxonomy__in=taxonomy_tags))
                               .order_by("pk")):
            if tag.taxonomy in taxonomy_tags:
                taxonomy_tags[tag.taxonomy].append(tag)
            tags[tag.name] = tag
        pbac_requests = {tag.pk: TagAnyMachineRequest(self.request.user, tag) for tag in tags.values()}
        engine.authorize_requests(list(pbac_requests.values()))
        for pbac_request in pbac_requests.values():
            if not pbac_request.is_authorized:
                logger.error("Permission denied %s", pbac_request, extra={"request": self.request})

        def is_authorized(tag):
            return pbac_requests[tag.pk].is_authorized

        # A refused tag gets the answer of an unknown tag. A SET operation removes the other tags of its
        # taxonomy, so a taxonomy with a refused tag gets the answer of an unknown taxonomy. A SET operation
        # gives the tags of its taxonomy only: a tag of another taxonomy gets the answer of an unknown tag.
        # A taxonomy without tags gets the answer of an unknown taxonomy too: a SET operation on it would
        # change nothing, with no decision, and its answer would count the machines of the principal users.
        errors = {}
        tags_to_set = {}
        self.tags_to_add = []
        self.tags_to_remove = []
        for index, operation in enumerate(operations):
            operation_errors = {}
            taxonomy = None
            if operation["kind"] == "SET":
                taxonomy = taxonomies.get(operation["taxonomy"])
                if (
                    taxonomy is None
                    or not taxonomy_tags[taxonomy]
                    or not all(is_authorized(tag) for tag in taxonomy_tags[taxonomy])
                ):
                    operation_errors["taxonomy"] = ["Unknown taxonomy."]
                operation_known_tags = {tag.name: tag for tag in taxonomy_tags.get(taxonomy, [])}
            else:
                operation_known_tags = tags
            operation_tags = []
            name_errors = {}
            for name_index, name in enumerate(operation["names"]):
                tag = operation_known_tags.get(name)
                if tag is None or not is_authorized(tag):
                    name_errors[name_index] = ["Unknown tag."]
                else:
                    operation_tags.append(tag)
            if name_errors:
                operation_errors["names"] = name_errors
            if operation_errors:
                errors[index] = operation_errors
            elif operation["kind"] == "SET":
                # the SET operations on one taxonomy give the tags of all of them
                tags_to_set.setdefault(taxonomy, []).extend(operation_tags)
            elif operation["kind"] == "ADD":
                self.tags_to_add.extend(operation_tags)
            else:
                self.tags_to_remove.extend(operation_tags)
        if errors:
            raise ValidationError({"operations": errors})
        self.tags_to_set = [(set_tags, [tag for tag in taxonomy_tags[taxonomy] if tag not in set_tags])
                            for taxonomy, set_tags in tags_to_set.items()]

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
        for tags, other_tags in self.tags_to_set:
            total_added += add_machine_tags(serial_number, tags, self.request)
            total_removed += remove_machine_tags(serial_number, other_tags, self.request)
        total_added += add_machine_tags(serial_number, self.tags_to_add, self.request)
        total_removed += remove_machine_tags(serial_number, self.tags_to_remove, self.request)
        return total_removed, total_added

    def _update(self):
        self._resolve_tags()
        found_machines = 0
        total_removed = 0
        total_added = 0
        for serial_number in self._iter_serial_numbers():
            found_machines += 1
            removed, added = self._update_machine_tags(serial_number)
            total_removed += removed
            total_added += added
        # The foreign keys of the machine tags are deferred. Without this check, a tag that another request
        # deleted would fail the commit, after the response.
        connection.check_constraints()
        return {"machines": {"found": found_machines},
                "tags": {"added": total_added,
                         "removed": total_removed}}

    def post(self, request, *args, **kwargs):
        serializer = MachineTagsUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.data = serializer.data
        # Another request can delete a tag of this one, or deadlock with it. The operation then runs again from
        # the start, so a deleted tag gets the answer of an unknown tag.
        attempt = 1
        while True:
            try:
                with transaction.atomic():
                    return Response(self._update())
            except (IntegrityError, OperationalError) as e:
                if attempt >= self.max_attempts or (
                    isinstance(e, OperationalError) and not isinstance(e.__cause__, DeadlockDetected)
                ):
                    raise
                logger.warning("Mass tagging attempt %s failed: %s", attempt, e, extra={"request": request})
                attempt += 1


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
    permission_required = "inventory.change_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        serializer = MachineSerialNumbersSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        count = archive_machine_snapshots(serializer.data["serial_numbers"],
                                          event_request=EventRequest.build_from_request(request))
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


# Machine and apps reports based on the UI views


class MachinesExport(APIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "inventory.view_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        export_format = request.GET.get("export_format", "xlsx")
        if export_format not in ("xlsx", "zip"):
            raise ValidationError("Unknown export format")
        msquery = MSQuery(request.GET)
        filename = "inventory_export_{:%Y-%m-%d_%H-%M-%S}.{}".format(timezone.now(), export_format)
        result = export_inventory.apply_async(
            (msquery.get_urlencoded_canonical_query_dict(), filename),
            {'task_user': request.user.id}
        )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class BaseAppsExport(APIView):
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
        result = self.task.apply_async((request.data, filename,), {'task_user': request.user.id})
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
        result = export_machine_android_apps.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineDebPackagesExport(APIView):
    permission_required = "inventory.view_debpackage"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_deb_packages.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineIOSAppsExport(APIView):
    permission_required = "inventory.view_iosapp"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_ios_apps.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineMacOSAppInstancesExport(APIView):
    permission_required = ("inventory.view_osxapp", "inventory.view_osxappinstance")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_macos_app_instances.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineProgramInstancesExport(APIView):
    permission_required = ("inventory.view_program", "inventory.view_programinstance")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_program_instances.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


class MachineSnapshotsExport(APIView):
    permission_required = ("inventory.view_machinesnapshot",)
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        source_name = request.query_params.get('source_name')
        result = export_machine_snapshots.apply_async(
            kwargs={"source_name": source_name, 'task_user': request.user.id}
            )
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


# Cleanup


class CleanupInventory(APIView):
    """
    Start inventory cleanup task
    """
    permission_required = ("inventory.delete_machinesnapshot",)
    permission_classes = [DjangoPermissionRequired]
    parser_classes = [FormParser, JSONParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = CleanupInventorySerializer(data=request.data)
        if serializer.is_valid():
            event_request = EventRequest.build_from_request(request)
            result = cleanup_inventory.apply_async(
                (serializer.data["days"], event_request.serialize(),),
                {"task_user": request.user.id}
            )
            return Response({"task_id": result.id,
                             "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                            status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Full export


class FullExport(APIView):
    permission_required = "inventory.view_machinesnapshot"
    permission_classes = [DjangoPermissionRequired]
    parser_classes = [FormParser, JSONParser, MultiPartParser]

    def post(self, request, *args, **kwargs):
        serializer = FullExportSerializer(data=request.data)
        if serializer.is_valid():
            result = export_full_inventory.apply_async(
                kwargs={"tables": serializer.validated_data.get("tables"),
                        "export_format": serializer.validated_data["export_format"],
                        "task_user": request.user.id}
            )
            return Response({"task_id": result.id,
                             "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                            status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Standard DRF views


class JMESPathCheckFilter(filters.FilterSet):
    name = filters.CharFilter(field_name="compliance_check__name")


class JMESPathCheckList(ListCreateAPIViewWithAudit):
    """
    List, search by name or create JMESPath compliance checks.
    """
    queryset = JMESPathCheck.objects.select_related("compliance_check").all()
    serializer_class = JMESPathCheckSerializer
    filterset_class = JMESPathCheckFilter


class JMESPathCheckDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a JMESPath compliance check.
    """
    queryset = JMESPathCheck.objects.select_related("compliance_check").all()
    serializer_class = JMESPathCheckSerializer


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
