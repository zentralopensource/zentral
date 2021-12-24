import logging
from django.utils.functional import cached_property
from zentral.core.compliance_checks import register_compliance_check_class
from zentral.core.compliance_checks.compliance_checks import BaseComplianceCheck
from zentral.core.compliance_checks.models import ComplianceCheck, Status
from zentral.core.compliance_checks.utils import update_machine_statuses
from zentral.core.events import event_cls_from_type
from .models import Query


logger = logging.getLogger("zentral.contrib.osquery.compliance_checks")


class OsqueryCheck(BaseComplianceCheck):
    model_display = "Osquery check"
    required_view_permissions = ("osquery.view_pack", "osquery.view_packquery")
    scoped_cc_query = (
        "select cc.model, cc.id, cc.name, cc.version "
        "from compliance_checks_compliancecheck as cc "
        "join osquery_query as q on (q.compliance_check_id = cc.id) "
        "join osquery_packquery as pq on (pq.query_id = q.id) "
        "join osquery_configurationpack as cp on (cp.pack_id = pq.pack_id) "
        "left join osquery_configurationpack_tags as cpt on (cpt.configurationpack_id = cp.id) "
        "join osquery_enrollment as e on (e.configuration_id = cp.configuration_id) "
        "join osquery_enrolledmachine as em on (em.enrollment_id = e.id) "
        "where cpt.tag_id is null or cpt.tag_id = any (%(tag_ids)s) "
        "and em.serial_number = %(serial_number)s"
    )

    @cached_property
    def query(self):
        try:
            return self.compliance_check.query
        except Query.DoesNotExist:
            return

    def get_redirect_url(self):
        return self.query.get_absolute_url()


register_compliance_check_class(OsqueryCheck)


def sync_query_compliance_check(query, on):
    "Create update or delete the query compliance check"
    created = updated = deleted = False
    if on:
        if not isinstance(query.version, int):
            query.refresh_from_db()
        cc_defaults = {
            "model": OsqueryCheck.get_model(),
            "name": query.name,
            "version": query.version,
            "description": query.description
        }
        if not query.compliance_check:
            query.compliance_check = ComplianceCheck.objects.create(**cc_defaults)
            query.save()
            created = True
        else:
            for key, val in cc_defaults.items():
                if getattr(query.compliance_check, key) != val:
                    setattr(query.compliance_check, key, val)
                    updated = True
            if updated:
                query.compliance_check.save()
    elif query.compliance_check:
        query.compliance_check.delete()
        deleted = True
    return created, updated, deleted


class ComplianceCheckStatusAggregator:
    def __init__(self, serial_number):
        self.serial_number = serial_number
        self.cc_statuses = {}

    def add_result(self, query_pk, query_version, status_time, results, distributed_query_pk=None):
        try:
            status = max(Status[r["ztl_status"].upper()] for r in results)
        except Exception:
            status = Status.UNKNOWN
        update_key = False
        try:
            _, _, stored_status_time, _ = self.cc_statuses[query_pk]
        except KeyError:
            update_key = True
        else:
            if status_time and stored_status_time:
                update_key = status_time > stored_status_time
        if update_key:
            self.cc_statuses[query_pk] = (query_version, status, status_time, distributed_query_pk)

    def commit(self):
        if not self.cc_statuses:
            return
        compliance_check_statuses = []
        checks = {}
        for query in (Query.objects.select_related("compliance_check")
                                   .prefetch_related("packquery__pack")
                                   .filter(pk__in=self.cc_statuses.keys(),
                                           compliance_check__isnull=False)):
            query_version, status, status_time, distributed_query_pk = self.cc_statuses[query.pk]
            if query.version != query_version:
                # outdated status
                continue
            compliance_check_statuses.append((query.compliance_check, status, status_time))
            checks[query.compliance_check.pk] = (query, status_time, distributed_query_pk)
        status_updates = update_machine_statuses(self.serial_number, compliance_check_statuses)
        event_cls = event_cls_from_type("osquery_check_status_updated")  # import cycle with osquery.events
        for compliance_check_pk, status_value, previous_status_value in status_updates:
            if status_value == previous_status_value:
                # status not updated, no event
                continue
            query, status_time, distributed_query_pk = checks[compliance_check_pk]
            yield event_cls.build_from_query_serial_number_and_statuses(
                query, distributed_query_pk,
                self.serial_number,
                Status(status_value), status_time,
                Status(previous_status_value) if previous_status_value is not None else None,
            )

    def commit_and_post_events(self):
        for event in self.commit():
            event.post()
