import base64

from django.db import transaction
from django.db.models import F
from django.http import HttpResponse
from django_filters import rest_framework as filters
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_yaml.parsers import YAMLParser
from zentral.contrib.inventory.models import File, Tag
from zentral.contrib.santa.utils import build_configuration_plist, build_configuration_profile
from zentral.utils.drf import DefaultDjangoModelPermissions, DjangoPermissionRequired
from .events import post_santa_ruleset_update_events
from .models import Configuration, Rule, RuleSet, Target, Enrollment, translate_rule_policy
from .serializers import (RuleSerializer, RuleSetUpdateSerializer, ConfigurationSerializer,
                          EnrollmentSerializer, build_file_tree_from_santa_fileinfo)
from .tasks import export_targets


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


class EnrollmentConfiguration(APIView):
    """
    base enrollment configuration class. To be subclassed.
    """
    permission_required = "santa.view_enrollment"
    permission_classes = [DjangoPermissionRequired]
    configuration = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"])
        if self.configuration == "configuration_plist":
            filename, content = build_configuration_plist(enrollment)
            content_type = "application/x-plist"
        elif self.configuration == "configuration_profile":
            filename, content = build_configuration_profile(enrollment)
            content_type = "application/octet-stream"
        else:
            raise ValidationError("Unknown enrollment configuration response type: {}".format(self.configuration))

        response = HttpResponse(content, content_type=content_type)
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        response["Content-Length"] = len(content)

        return response


class EnrollmentConfigurationPlist(EnrollmentConfiguration):
    """
    Download enrollment plist file
    """
    configuration = "configuration_plist"


class EnrollmentConfigurationProfile(EnrollmentConfiguration):
    """
    Download enrollment configuration_profile
    """
    configuration = "configuration_profile"


class IngestFileInfo(APIView):
    parser_classes = [JSONParser]
    permission_required = "inventory.add_file"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        data = request.data
        if isinstance(data, dict):
            data = [data]
        deserialization_errors = 0
        db_errors = 0
        present = 0
        added = 0
        ignored = 0
        for fi_d in data:
            # only dicts
            if not isinstance(fi_d, dict):
                deserialization_errors += 1
                continue
            # only Executable fileinfo
            fi_type = fi_d.get("Type")
            if not fi_type:
                deserialization_errors += 1
                continue
            elif not fi_type.startswith("Executable"):
                ignored += 1
                continue
            # build tree
            try:
                file_d = build_file_tree_from_santa_fileinfo(fi_d)
            except Exception:
                deserialization_errors += 1
                continue
            # commit File
            try:
                _, created = File.objects.commit(file_d)
            except Exception:
                db_errors += 1
            else:
                if created:
                    added += 1
                else:
                    present += 1
        return Response({"deserialization_errors": deserialization_errors,
                         "db_errors": db_errors,
                         "present": present,
                         "added": added,
                         "ignored": ignored})


class RuleFilter(filters.FilterSet):
    identifier = filters.CharFilter(field_name="target__identifier")
    type = filters.ChoiceFilter(field_name="target__type", choices=Target.TYPE_CHOICES)
    configuration = filters.ModelChoiceFilter(queryset=Configuration.objects.all())


class RuleList(generics.ListAPIView):
    """
    List or search rules.
    """
    queryset = Rule.objects.select_related("configuration", "ruleset", "target")
    permission_classes = (DefaultDjangoModelPermissions,)
    serializer_class = RuleSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = RuleFilter


class RuleSetUpdate(APIView):
    parser_classes = [JSONParser, YAMLParser]
    permission_required = ("santa.add_ruleset", "santa.change_ruleset",
                           "santa.add_rule", "santa.change_rule", "santa.delete_rule")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        dry_run_arg = request.GET.get("dryRun")
        dry_run = isinstance(dry_run_arg, str) and dry_run_arg in ("", "All")
        serializer = RuleSetUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        ruleset, ruleset_created = RuleSet.objects.get_or_create(name=data["name"])
        ruleset_update_event = {
            "ruleset": ruleset.serialize_for_event(),
            "dry_run": dry_run,
            "result": "created" if ruleset_created else "present"
        }
        RuleSet.objects.select_for_update().filter(pk=ruleset.pk)
        rule_update_events = []
        all_tags = {tag_name: Tag.objects.get_or_create(name=tag_name)[0]
                    for tag_name in serializer.all_tag_names()}
        for configuration in serializer.configurations:
            rules_created = rules_deleted = rules_present = rules_updated = 0
            found_target_pks = []
            for rule_dict in data["rules"]:
                rule_defaults = rule_dict.copy()
                target, _ = Target.objects.get_or_create(type=rule_defaults.pop("rule_type"),
                                                         identifier=rule_defaults.pop("identifier"))
                found_target_pks.append(target.pk)
                tags = set(all_tags[n] for n in rule_defaults.pop("tags", []))
                excluded_tags = set(all_tags[n] for n in rule_defaults.pop("excluded_tags", []))
                rule, rule_created = Rule.objects.get_or_create(
                    configuration=configuration,
                    ruleset=ruleset,
                    target=target,
                    defaults=rule_defaults
                )
                if rule_created:
                    rule.tags.set(tags)
                    rule.excluded_tags.set(excluded_tags)
                    rules_created += 1
                    rule_update_events.append({
                        "rule": rule.serialize_for_event(),
                        "result": "created"
                    })
                else:
                    rule_updated = False
                    rule_updates = {}
                    if rule.policy != rule_defaults["policy"]:
                        rule_updates.setdefault("removed", {})["policy"] = translate_rule_policy(rule.policy)
                        rule.policy = rule_defaults["policy"]
                        rule_updates.setdefault("added", {})["policy"] = translate_rule_policy(rule.policy)
                        rule_updated = True
                    custom_msg = rule_defaults.get("custom_msg", "")
                    if rule.custom_msg != custom_msg:
                        if rule.custom_msg:
                            rule_updates.setdefault("removed", {})["custom_msg"] = rule.custom_msg
                        rule.custom_msg = custom_msg
                        if rule.custom_msg:
                            rule_updates.setdefault("added", {})["custom_msg"] = rule.custom_msg
                        rule.version = F("version") + 1
                        rule_updated = True
                    description = rule_defaults.get("description", "")
                    if rule.description != description:
                        if rule.description:
                            rule_updates.setdefault("removed", {})["description"] = rule.description
                        rule.description = description
                        if rule.description:
                            rule_updates.setdefault("added", {})["description"] = rule.description
                        rule_updated = True
                    serial_numbers = set(rule_defaults.get("serial_numbers", []))
                    old_serial_numbers = set(rule.serial_numbers)
                    if old_serial_numbers != serial_numbers:
                        removed_serial_numbers = old_serial_numbers - serial_numbers
                        if removed_serial_numbers:
                            rule_updates.setdefault("removed", {})["serial_numbers"] = sorted(removed_serial_numbers)
                        rule.serial_numbers = sorted(serial_numbers)
                        added_serial_numbers = serial_numbers - old_serial_numbers
                        if added_serial_numbers:
                            rule_updates.setdefault("added", {})["serial_numbers"] = sorted(added_serial_numbers)
                        rule_updated = True
                    excluded_serial_numbers = set(rule_defaults.get("excluded_serial_numbers", []))
                    old_excluded_serial_numbers = set(rule.excluded_serial_numbers)
                    if old_excluded_serial_numbers != excluded_serial_numbers:
                        removed_excluded_serial_numbers = old_excluded_serial_numbers - excluded_serial_numbers
                        if removed_excluded_serial_numbers:
                            rule_updates.setdefault("removed", {})["excluded_serial_numbers"] = sorted(
                                removed_excluded_serial_numbers
                            )
                        rule.excluded_serial_numbers = sorted(excluded_serial_numbers)
                        added_excluded_serial_numbers = excluded_serial_numbers - old_excluded_serial_numbers
                        if added_excluded_serial_numbers:
                            rule_updates.setdefault("added", {})["excluded_serial_numbers"] = sorted(
                                added_excluded_serial_numbers
                            )
                        rule_updated = True
                    primary_users = set(rule_defaults.get("primary_users", []))
                    old_primary_users = set(rule.primary_users)
                    if old_primary_users != primary_users:
                        removed_primary_users = old_primary_users - primary_users
                        if removed_primary_users:
                            rule_updates.setdefault("removed", {})["primary_users"] = sorted(removed_primary_users)
                        rule.primary_users = sorted(primary_users)
                        added_primary_users = primary_users - old_primary_users
                        if added_primary_users:
                            rule_updates.setdefault("added", {})["primary_users"] = sorted(added_primary_users)
                        rule_updated = True
                    excluded_primary_users = set(rule_defaults.get("excluded_primary_users", []))
                    old_excluded_primary_users = set(rule.excluded_primary_users)
                    if old_excluded_primary_users != excluded_primary_users:
                        removed_excluded_primary_users = old_excluded_primary_users - excluded_primary_users
                        if removed_excluded_primary_users:
                            rule_updates.setdefault("removed", {})["excluded_primary_users"] = sorted(
                                removed_excluded_primary_users
                            )
                        rule.excluded_primary_users = sorted(excluded_primary_users)
                        added_excluded_primary_users = excluded_primary_users - old_excluded_primary_users
                        if added_excluded_primary_users:
                            rule_updates.setdefault("added", {})["excluded_primary_users"] = sorted(
                                added_excluded_primary_users
                            )
                        rule_updated = True
                    old_tags = set(rule.tags.all())
                    if old_tags != tags:
                        removed_tags = old_tags - tags
                        if removed_tags:
                            rule_updates.setdefault("removed", {})["tags"] = [{"pk": t.pk, "name": t.name}
                                                                              for t in removed_tags]
                        rule.tags.set(tags)
                        added_tags = tags - old_tags
                        if added_tags:
                            rule_updates.setdefault("added", {})["tags"] = [{"pk": t.pk, "name": t.name}
                                                                            for t in added_tags]
                        rule_updated = True
                    old_excluded_tags = set(rule.excluded_tags.all())
                    if old_excluded_tags != excluded_tags:
                        removed_excluded_tags = old_excluded_tags - excluded_tags
                        if removed_excluded_tags:
                            rule_updates.setdefault("removed", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                                       for t in removed_excluded_tags]
                        rule.excluded_tags.set(excluded_tags)
                        added_excluded_tags = excluded_tags - old_excluded_tags
                        if added_excluded_tags:
                            rule_updates.setdefault("added", {})["excluded_tags"] = [{"pk": t.pk, "name": t.name}
                                                                                     for t in added_excluded_tags]
                        rule_updated = True
                    if rule_updated:
                        rule.save()
                        rules_updated += 1
                        rule_update_events.append({
                            "rule": rule.serialize_for_event(),
                            "result": "updated",
                            "updates": rule_updates
                        })
                    else:
                        rules_present += 1
            for rule in (Rule.objects.select_related("target")
                                     .prefetch_related("tags")
                                     .filter(configuration=configuration, ruleset=ruleset)
                                     .exclude(target__pk__in=found_target_pks)):
                rule_update_events.append({
                    "rule": rule.serialize_for_event(),
                    "result": "deleted"
                })
                rule.delete()
                rules_deleted += 1
            ruleset_update_event.setdefault("configurations", []).append(
                {"name": configuration.name,
                 "pk": configuration.pk,
                 "rule_results": {
                      "created": rules_created,
                      "deleted": rules_deleted,
                      "present": rules_present,
                      "updated": rules_updated,
                 }}
            )
        if dry_run:
            post_santa_ruleset_update_events(request, ruleset_update_event, [])
            transaction.set_rollback(True)
        else:
            transaction.on_commit(
                lambda: post_santa_ruleset_update_events(request, ruleset_update_event, rule_update_events)
            )
        return Response(ruleset_update_event)


class TargetsExport(APIView):
    permission_required = "santa.view_target"
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        query = request.GET.get("q")
        if query:
            query = query.strip()
        else:
            query = None
        target_type = request.GET.get("target_type")
        if target_type:
            if target_type not in (Target.BINARY, Target.BUNDLE, Target.CERTIFICATE, Target.TEAM_ID):
                raise ValidationError("Unknown target type")
        else:
            target_type = None
        export_format = request.GET.get("export_format", "xlsx")
        if export_format not in ("xlsx", "zip"):
            raise ValidationError("Unknown export format")
        filename = f"santa_targets_export_{timezone.now():%Y-%m-%d_%H-%M-%S}.{export_format}"
        result = export_targets.apply_async((query, target_type, filename))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)
