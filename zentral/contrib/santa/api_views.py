from django.db.models import F
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_yaml.parsers import YAMLParser
from zentral.contrib.inventory.models import File, Tag
from .models import Rule, RuleSet, Target
from .serializers import RuleSetUpdateSerializer, build_file_tree_from_santa_fileinfo


class IngestFileInfo(APIView):
    parser_classes = [JSONParser]

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


class RuleSetUpdate(APIView):
    parser_classes = [JSONParser, YAMLParser]

    def post(self, request, *args, **kwargs):
        serializer = RuleSetUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        ruleset, ruleset_created = RuleSet.objects.get_or_create(name=data["name"])
        response = {"ruleset": {
                      "pk": ruleset.pk,
                      "name": ruleset.name,
                      "result": "created" if ruleset_created else "present"
                    }}
        all_tags = {tag_name: Tag.objects.get_or_create(name=tag_name)[0]
                    for tag_name in serializer.all_tag_names()}
        for configuration in serializer.configurations:
            rules_created = rules_deleted = rules_present = rules_updated = 0
            found_target_pks = []
            for rule_dict in data["rules"]:
                rule_defaults = rule_dict.copy()
                target, _ = Target.objects.get_or_create(type=rule_defaults.pop("rule_type"),
                                                         sha256=rule_defaults.pop("sha256"))
                found_target_pks.append(target.pk)
                tags = set(all_tags[n] for n in rule_defaults.pop("tags", []))
                rule, rule_created = Rule.objects.get_or_create(
                    configuration=configuration,
                    ruleset=ruleset,
                    target=target,
                    defaults=rule_defaults
                )
                if rule_created:
                    rule.tags.set(tags)
                    rules_created += 1
                else:
                    rule_updated = False
                    if rule.policy != rule_defaults["policy"]:
                        rule.policy = rule_defaults["policy"]
                        rule_updated = True
                    custom_msg = rule_defaults.get("custom_msg", "")
                    if rule.custom_msg != custom_msg:
                        rule.custom_msg = custom_msg
                        rule.version = F("version") + 1
                        rule_updated = True
                    serial_numbers = set(rule_defaults.get("serial_numbers", []))
                    if set(rule.serial_numbers) != serial_numbers:
                        rule.serial_numbers = sorted(serial_numbers)
                        rule_updated = True
                    primary_users = set(rule_defaults.get("primary_users", []))
                    if set(rule.primary_users) != primary_users:
                        rule.primary_users = sorted(primary_users)
                        rule_updated = True
                    if set(rule.tags.all()) != tags:
                        rule.tags.set(tags)
                        rule_updated = True
                    if rule_updated:
                        rule.save()
                        rules_updated += 1
                    else:
                        rules_present += 1
            rules_deleted = (Rule.objects.filter(configuration=configuration,
                                                 ruleset=ruleset)
                                         .exclude(target__pk__in=found_target_pks)
                                         .delete())[1].get("santa.Rule", 0)
            response.setdefault("configurations", []).append(
                {"name": configuration.name,
                 "pk": configuration.pk,
                 "rule_results": {
                      "created": rules_created,
                      "deleted": rules_deleted,
                      "present": rules_present,
                      "updated": rules_updated,
                 }}
            )
        return Response(response)
