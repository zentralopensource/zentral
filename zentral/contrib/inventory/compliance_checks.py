import logging
import threading
import time
from django.utils.functional import cached_property, SimpleLazyObject
import jmespath
from zentral.core.compliance_checks import register_compliance_check_class
from zentral.core.compliance_checks.compliance_checks import BaseComplianceCheck
from zentral.core.compliance_checks.models import Status
from zentral.core.compliance_checks.utils import update_machine_statuses
from .events import JMESPathCheckStatusUpdated
from .models import JMESPathCheck, MachineTag


logger = logging.getLogger("zentral.contrib.inventory.compliance_checks")


class InventoryJMESPathCheck(BaseComplianceCheck):
    model_display = "Inventory JMESPath check"
    required_view_permissions = ("inventory.view_jmespathcheck",)
    scoped_cc_query = (
        "select cc.model, cc.id, cc.name, cc.version "
        "from compliance_checks_compliancecheck as cc "
        "join inventory_jmespathcheck as jc on (jc.compliance_check_id = cc.id) "
        "left join inventory_jmespathcheck_tags as jct on (jct.jmespathcheck_id = jc.id) "
        "where (jct.tag_id is null or jct.tag_id = any (%(tag_ids)s)) "
        "and lower(jc.source_name) in ("
        " select distinct lower(s.name)"
        " from inventory_source as s"
        " join inventory_currentmachinesnapshot as cms on (cms.source_id = s.id)"
        " where cms.serial_number = %(serial_number)s"
        ") and jc.platforms && array("
        " select platform from inventory_machinesnapshot as ms"
        " join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)"
        " where cms.serial_number = %(serial_number)s"
        ")"
    )

    @cached_property
    def jmespath_check(self):
        try:
            return self.compliance_check.jmespath_check
        except JMESPathCheck.DoesNotExist:
            return

    def get_redirect_url(self):
        return self.jmespath_check.get_absolute_url()


register_compliance_check_class(InventoryJMESPathCheck)


class JMESPathChecksCache:
    # TODO: hard coded ttl
    ttl = 300  # cache ttl in seconds

    def __init__(self):
        self._source_platform_checks = {}
        self._checks = {}
        self._last_fetched_time = None
        self._lock = threading.Lock()

    def _load(self):
        if self._last_fetched_time is not None and (time.monotonic() - self._last_fetched_time) < self.ttl:
            return
        self._source_platform_checks = {}
        self._checks = {}
        for jmespath_check in (JMESPathCheck.objects.select_related("compliance_check")
                                                    .prefetch_related("tags")
                                                    .all()):
            source_name = jmespath_check.source_name.lower()
            tags_set = frozenset(tag.id for tag in jmespath_check.tags.all())
            compiled_jmespath_expression = jmespath.compile(jmespath_check.jmespath_expression)
            for platform in jmespath_check.platforms:
                self._source_platform_checks.setdefault((source_name, platform), []).append(
                    (tags_set, compiled_jmespath_expression, jmespath_check)
                )
            self._checks[jmespath_check.compliance_check.pk] = jmespath_check
        self._last_fetched_time = time.monotonic()

    def _get_source_platform_checks(self, source_name, platform):
        with self._lock:
            self._load()
            return self._source_platform_checks.get((source_name.lower(), platform), [])

    def process_tree(self, tree, last_seen):
        machine_tag_set = None
        compliance_check_statuses = []
        serial_number = tree["serial_number"]
        source_name = tree["source"]["name"]
        platform = tree.get("platform")
        if not platform:
            logger.warning("Cannot process %s %s tree: missing platform", source_name, serial_number)
            return
        for check_tag_set, jmespath_parsed_expr, jmespath_check in self._get_source_platform_checks(
            source_name,
            platform
        ):
            if check_tag_set:
                if machine_tag_set is None:
                    # TODO cache?
                    machine_tag_set = set(
                        MachineTag.objects.filter(serial_number=serial_number).values_list("tag_id", flat=True)
                    )
                if not check_tag_set.intersection(machine_tag_set):
                    # tags mismatch
                    continue
            # default to unknown status
            status = Status.UNKNOWN
            try:
                result = jmespath_parsed_expr.search(tree)
            except Exception:
                logger.exception("Could not evaluate JMESPath check %s", jmespath_check.pk)
            else:
                if result is True:
                    status = Status.OK
                elif result is False:
                    status = Status.FAILED
                else:
                    logger.warning("JMESPath check %s result is not a boolean", jmespath_check.pk)
            compliance_check_statuses.append((jmespath_check.compliance_check, status, last_seen))
        if not compliance_check_statuses:
            # nothing to update, no events
            return
        status_updates = update_machine_statuses(serial_number, compliance_check_statuses)
        for compliance_check_pk, status_value, previous_status_value in status_updates:
            if status_value == previous_status_value:
                # status not updated, no event
                continue
            yield JMESPathCheckStatusUpdated.build_from_object_serial_number_and_statuses(
                self._checks[compliance_check_pk],
                serial_number,
                Status(status_value),
                Status(previous_status_value) if previous_status_value is not None else None
            )


jmespath_checks_cache = SimpleLazyObject(lambda: JMESPathChecksCache())
