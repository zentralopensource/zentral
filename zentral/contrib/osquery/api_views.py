import codecs
import json
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import F
from django_filters import rest_framework as filters
from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import generics, serializers, status
from rest_framework.exceptions import ParseError, ValidationError
from rest_framework.parsers import BaseParser, JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_yaml.parsers import YAMLParser
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .compliance_checks import sync_query_compliance_check
from .events import post_osquery_pack_update_events
from .models import Configuration, Enrollment, Pack, PackQuery, Query, AutomaticTableConstruction, FileCategory, \
    ConfigurationPack
from .linux_script.builder import OsqueryZentralEnrollScriptBuilder
from .osx_package.builder import OsqueryZentralEnrollPkgBuilder
from .powershell_script.builder import OsqueryZentralEnrollPowershellScriptBuilder
from .serializers import ConfigurationPackSerializer, ConfigurationSerializer, EnrollmentSerializer, \
    OsqueryPackSerializer, QuerySerializer, AutomaticTableConstructionSerializer, \
    FileCategorySerializer, PackSerializer
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


class OsqueryConfigParser(BaseParser):
    media_type = 'application/x-osquery-conf'

    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)
        try:
            # https://github.com/osquery/osquery/pull/2785
            # https://github.com/osquery/osquery/issues/1689
            decoded_stream = codecs.getreader(encoding)(stream).read()
            sink = ""
            for line in decoded_stream.replace("\\\n", "").splitlines():
                line = line.strip()
                if line.startswith("#") or line.startswith("//"):
                    continue
                sink += line + "\n"
            return json.loads(sink)
        except ValueError:
            raise ParseError('Osquery config parse error')


class PackView(APIView):
    parser_classes = [JSONParser, OsqueryConfigParser, YAMLParser]

    def put(self, request, *args, **kwargs):
        if not request.user.has_perms(
            ("osquery.add_pack", "osquery.change_pack",
             "osquery.add_packquery", "osquery.add_query", "osquery.change_packquery", "osquery.delete_packquery")
        ):
            raise PermissionDenied("Not allowed")
        serializer = OsqueryPackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # create or update pack
        slug = kwargs["slug"]
        pack_defaults = serializer.get_pack_defaults(slug)
        if Pack.objects.exclude(slug=slug).filter(name=pack_defaults["name"]).exists():
            raise serializers.ValidationError(
                {'name': 'A pack with the same name but a different slug already exists'}
            )
        pack, pack_created = Pack.objects.get_or_create(slug=slug, defaults=pack_defaults)
        Pack.objects.select_for_update().filter(pk=pack.pk)
        pack_update_event = {}
        if pack_created:
            pack_update_event["result"] = "created"
        else:
            pack_updated = False
            pack_updates = {}
            for attr, new_val in pack_defaults.items():
                old_val = getattr(pack, attr)
                if old_val != new_val:
                    setattr(pack, attr, new_val)
                    pack_updated = True
                    if old_val:
                        pack_updates.setdefault("removed", {})[attr] = old_val
                    if new_val:
                        pack_updates.setdefault("added", {})[attr] = new_val
            if pack_updated:
                pack.save()
                pack_update_event["result"] = "updated"
                pack_update_event["updates"] = pack_updates
            else:
                pack_update_event["result"] = "present"

        # create update or delete pack queries
        pack_queries_created = pack_queries_deleted = pack_queries_present = pack_queries_updated = 0
        pack_query_update_events = []
        found_query_slugs = []
        for query_slug, pack_query_defaults, query_defaults in serializer.iter_query_defaults(slug):
            found_query_slugs.append(query_slug)
            compliance_check = query_defaults.pop("compliance_check")
            try:
                pack_query = pack.packquery_set.select_related("query").get(slug=query_slug)
            except PackQuery.DoesNotExist:
                # update or create query
                query_name = query_defaults.pop("name")
                query, query_created = Query.objects.get_or_create(name=query_name, defaults=query_defaults)
                if not query_created:
                    query_updated = False
                    query_sql_updated = False
                    for attr, new_val in query_defaults.items():
                        query_updated = True
                        old_val = getattr(query, attr)
                        if old_val != new_val:
                            setattr(query, attr, new_val)
                            if attr == "sql":
                                query_sql_updated = True
                                query.version = F("version") + 1
                    if query_updated:
                        query.save()
                        if query_sql_updated:
                            query.refresh_from_db()

                # create, update or delete compliance check
                sync_query_compliance_check(query, compliance_check)

                # create pack query
                pack_query = PackQuery.objects.create(pack=pack, query=query, **pack_query_defaults)
                pack_queries_created += 1
                pack_query_update_events.append({
                    "pack_query": pack_query.serialize_for_event(),
                    "result": "created"
                })
                continue

            # update pack query
            pack_query_updated = False
            pack_query_updates = {}
            for attr, new_val in pack_query_defaults.items():
                old_val = getattr(pack_query, attr)
                if old_val != new_val:
                    if old_val:
                        pack_query_updates.setdefault("removed", {})[attr] = old_val
                    if new_val:
                        pack_query_updates.setdefault("added", {})[attr] = new_val
                    setattr(pack_query, attr, new_val)
                    pack_query_updated = True
            if pack_query_updated:
                pack_query.save()

            # update query
            query = pack_query.query
            query_updated = False
            query_sql_updated = False
            for attr, new_val in query_defaults.items():
                old_val = getattr(query, attr)
                if old_val != new_val:
                    reported_attr = attr
                    if attr == "sql":
                        query_sql_updated = True
                        reported_attr = "query"
                    if old_val:
                        pack_query_updates.setdefault("removed", {})[reported_attr] = old_val
                    if new_val:
                        pack_query_updates.setdefault("added", {})[reported_attr] = new_val
                    setattr(query, attr, new_val)
                    if query_sql_updated:
                        query.version = F("version") + 1
                    query_updated = True
            if query_updated:
                query.save()
                if query_sql_updated:
                    query.refresh_from_db()

            # create, update or delete compliance check
            cc_created, cc_updated, cc_deleted = sync_query_compliance_check(query, compliance_check)

            if pack_query_updated or query_updated or cc_created or cc_updated or cc_deleted:
                pack_queries_updated += 1
                pack_query_update_events.append({
                    "pack_query": pack_query.serialize_for_event(),
                    "result": "updated",
                    "updates": pack_query_updates
                })
            else:
                pack_queries_present += 1

        # delete extra pack queries
        for pack_query in pack.packquery_set.select_related("pack", "query").exclude(slug__in=found_query_slugs):
            pack_query_update_events.append({
                "pack_query": pack_query.serialize_for_event(),
                "result": "deleted"
            })
            pack_query.delete()
            pack_queries_deleted += 1

        pack_update_event["query_results"] = {
            "created": pack_queries_created,
            "deleted": pack_queries_deleted,
            "present": pack_queries_present,
            "updated": pack_queries_updated
        }

        full_pack_update_event = pack_update_event.copy()
        full_pack_update_event["pack"] = pack.serialize_for_event()

        transaction.on_commit(
            lambda: post_osquery_pack_update_events(request, full_pack_update_event, pack_query_update_events)
        )

        pack_update_event["pack"] = pack.serialize_for_event(short=True)
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
            raise ValidationError("Unknown export format")
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

class QueryList(generics.ListCreateAPIView):
    queryset = Query.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = QuerySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class QueryDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Query.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = QuerySerializer


# Configuration Packs

class ConfigurationPackFilter(filters.FilterSet):
    pack_id = filters.NumberFilter(field_name="pack_id")
    configuration_id = filters.NumberFilter(field_name="configuration_id")


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
