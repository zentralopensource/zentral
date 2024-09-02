from django.core.exceptions import PermissionDenied
from django.db import transaction
from django_filters import rest_framework as filters
from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import generics, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_yaml.parsers import YAMLParser
from accounts.api_authentication import APITokenAuthentication
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .events import post_osquery_pack_update_events
from .models import Configuration, ConfigurationPack, Enrollment, Pack, Query, AutomaticTableConstruction, FileCategory
from .linux_script.builder import OsqueryZentralEnrollScriptBuilder
from .osx_package.builder import OsqueryZentralEnrollPkgBuilder
from .packs import OsqueryConfigParser, update_or_create_pack
from .powershell_script.builder import OsqueryZentralEnrollPowershellScriptBuilder
from .serializers import (ConfigurationPackSerializer, ConfigurationSerializer, EnrollmentSerializer,
                          QuerySerializer, AutomaticTableConstructionSerializer,
                          FileCategorySerializer, PackSerializer)
from .tasks import export_distributed_query_results


class AutomaticTableConstructionFilter(filters.FilterSet):
    configuration_id = filters.ModelChoiceFilter(field_name='configuration', queryset=Configuration.objects.all())
    name = filters.CharFilter()


class AutomaticTableConstructionList(generics.ListCreateAPIView):
    """
    List all AutomaticTableConstructions or create a new AutomaticTableConstruction
    """
    queryset = AutomaticTableConstruction.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = AutomaticTableConstructionSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AutomaticTableConstructionFilter


class AutomaticTableConstructionDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete an AutomaticTableConstruction instance.
    """
    queryset = AutomaticTableConstruction.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = AutomaticTableConstructionSerializer


class ConfigurationList(generics.ListCreateAPIView):
    """
    List all Configurations, search Configuration by name, or create a new Configuration.
    """
    queryset = Configuration.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class ConfigurationDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a Configuration instance.
    """
    queryset = Configuration.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This configuration cannot be deleted')
        else:
            return super().perform_destroy(instance)


class EnrollmentList(generics.ListCreateAPIView):
    """
    List all Enrollments or create a new Enrollment
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer


class EnrollmentDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete an Enrollment instance.
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This enrollment cannot be deleted')
        else:
            return super().perform_destroy(instance)


class EnrollmentArtifact(APIView):
    """
    base enrollment artifact class. To be subclassed.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "osquery.view_enrollment"
    permission_classes = [DjangoPermissionRequired]
    builder_class = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=self.kwargs["pk"])
        self.builder = self.builder_class(enrollment)
        return self.do_get()


class EnrollmentPackage(EnrollmentArtifact):
    """
    Download macOS enrollment package
    """
    builder_class = OsqueryZentralEnrollPkgBuilder

    def do_get(self):
        return self.builder.get_conditional_response(self.request)


class EnrollmentPowershellScript(EnrollmentArtifact):
    """
    Download enrollment powershell script
    """
    builder_class = OsqueryZentralEnrollPowershellScriptBuilder

    def do_get(self):
        return self.builder.build_and_make_response()


class EnrollmentScript(EnrollmentArtifact):
    """
    Download enrollment bash script
    """
    builder_class = OsqueryZentralEnrollScriptBuilder

    def do_get(self):
        return self.builder.build_and_make_response()


# File categories

class FileCategoryFilter(filters.FilterSet):
    configuration_id = filters.ModelChoiceFilter(field_name='configuration', queryset=Configuration.objects.all())
    name = filters.CharFilter()


class FileCategoryList(generics.ListCreateAPIView):
    """
    List, Create file categories, search by name or configuration_id
    """
    queryset = FileCategory.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = FileCategorySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = FileCategoryFilter


class FileCategoryDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, Update, Delete a file category
    """
    queryset = FileCategory.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = FileCategorySerializer


# Standard Osquery packs

class PackView(APIView):
    parser_classes = [JSONParser, OsqueryConfigParser, YAMLParser]

    def put(self, request, *args, **kwargs):
        if not request.user.has_perms(
            ("osquery.add_pack", "osquery.change_pack",
             "osquery.add_packquery", "osquery.add_query", "osquery.change_packquery", "osquery.delete_packquery")
        ):
            raise PermissionDenied("Not allowed")
        pack_update_event = update_or_create_pack(request, request.data, slug=kwargs["slug"])
        return Response(pack_update_event)

    def delete(self, request, *args, **kwargs):
        if not request.user.has_perms(("osquery.delete_pack", "osquery.delete_packquery")):
            raise PermissionDenied("Not allowed")
        try:
            pack = Pack.objects.select_for_update().get(slug=kwargs["slug"])
        except Pack.DoesNotExist:
            return Response({"pack": {"slug": kwargs["slug"]}, "result": "absent"},
                            status=status.HTTP_404_NOT_FOUND)

        # prepare the events
        pack_queries_deleted = 0
        pack_query_update_events = []
        for pack_query in pack.packquery_set.select_related("pack", "query").all():
            pack_query_update_events.append({
                "pack_query": pack_query.serialize_for_event(),
                "result": "deleted"
            })
            pack_queries_deleted += 1

        pack_update_event = {
            "result": "deleted",
            "query_results": {
                "created": 0,
                "deleted": pack_queries_deleted,
                "present": 0,
                "updated": 0
            }
        }

        full_pack_update_event = pack_update_event.copy()
        full_pack_update_event["pack"] = pack.serialize_for_event()

        transaction.on_commit(
            lambda: post_osquery_pack_update_events(request, full_pack_update_event, pack_query_update_events)
        )

        # prepare the response
        pack_update_event["pack"] = pack.serialize_for_event(short=True)

        # finally, delete the pack
        pack.delete()

        return Response(pack_update_event)


class ExportDistributedQueryResults(APIView):
    permission_required = ("osquery.view_distributedqueryresult",)
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        export_format = request.GET.get("export_format", "csv")
        if export_format not in ("csv", "ndjson", "xlsx"):
            raise ValidationError({"export_format": "Must be csv, ndjson or xlsx"})
        result = export_distributed_query_results.apply_async((int(kwargs["pk"]), f".{export_format}"))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


# Packs

class PackFilter(filters.FilterSet):
    configuration_id = filters.ModelChoiceFilter(field_name="configurationpack__configuration",
                                                 queryset=Configuration.objects.all())
    name = filters.CharFilter()


class PackList(generics.ListCreateAPIView):
    queryset = Pack.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = PackSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackFilter


class PackDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Pack.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = PackSerializer


# Queries

class QueryFilter(filters.FilterSet):
    pack_id = filters.ModelChoiceFilter(field_name="packquery__pack",
                                        queryset=Pack.objects.all())
    name = filters.CharFilter()


class QueryList(generics.ListCreateAPIView):
    queryset = Query.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = QuerySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = QueryFilter


class QueryDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Query.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = QuerySerializer


# Configuration Packs

class ConfigurationPackFilter(filters.FilterSet):
    pack_id = filters.ModelChoiceFilter(field_name="pack_id", queryset=Pack.objects.all())
    configuration_id = filters.ModelChoiceFilter(field_name="configuration_id",
                                                 queryset=Configuration.objects.all())


class ConfigurationPackList(generics.ListCreateAPIView):
    queryset = ConfigurationPack.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationPackSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = ConfigurationPackFilter


class ConfigurationPackDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ConfigurationPack.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = ConfigurationPackSerializer
