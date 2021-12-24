from datetime import datetime
from django.db import connection
import psycopg2.extras
from . import compliance_check_classes
from .compliance_checks import BaseComplianceCheck
from .models import Status


def update_machine_statuses(serial_number, compliance_check_statuses):
    query = (
        'insert into compliance_checks_machinestatus '
        '("compliance_check_id", "compliance_check_version", "serial_number", "status", "status_time") '
        'values %s '
        'on conflict ("compliance_check_id", "serial_number") do update '
        'set compliance_check_version = excluded.compliance_check_version,'
        'status = excluded.status, status_time = excluded.status_time,'
        'previous_status = compliance_checks_machinestatus.status '
        'where excluded.status_time > compliance_checks_machinestatus.status_time '
        'returning compliance_check_id, status, previous_status'
    )
    with connection.cursor() as cursor:
        now = datetime.utcnow()  # default status time
        result = psycopg2.extras.execute_values(
            cursor, query,
            ((compliance_check.pk,
              compliance_check.version,
              serial_number,
              status.value,
              status_time or now)
             for compliance_check, status, status_time in compliance_check_statuses),
            fetch=True
        )
        return result


def get_machine_compliance_check_statuses(serial_number, tags):
    compliance_check_statuses = []
    non_default_compliance_check_classes = [
        cc_cls for cc_cls in compliance_check_classes.values()
        if cc_cls != BaseComplianceCheck
    ]
    non_default_compliance_check_class_count = len(non_default_compliance_check_classes)
    if non_default_compliance_check_class_count < 1:
        return compliance_check_statuses
    scoped_cc_queries = " UNION ".join(cc_cls.scoped_cc_query for cc_cls in non_default_compliance_check_classes)
    if non_default_compliance_check_class_count < 2:
        # union will eliminate duplicates, but without union, a group by is needed
        scoped_cc_queries += " group by cc.model, cc.id, cc.name, cc.version"
    query = (
        f"with scoped_cc as ({scoped_cc_queries}) "
        "select cc.model, cc.id, cc.name, "
        "case when ms.compliance_check_version = cc.version then ms.status else null end as status,"
        "case when ms.compliance_check_version = cc.version then ms.status_time else null end as status_time "
        "from scoped_cc as cc "
        "left join compliance_checks_machinestatus as ms on (cc.id = ms.compliance_check_id) "
        "where ms.serial_number is null or ms.serial_number = %(serial_number)s "
        "order by cc.name"
    )
    with connection.cursor() as cursor:
        cursor.execute(
            query,
            {"serial_number": serial_number,
             "tag_ids": [t.id for t in tags] if tags else None}
        )
        for cc_model, cc_pk, cc_name, status, status_time in cursor.fetchall():
            if status is None:
                status = Status.PENDING
            else:
                status = Status(status)
            compliance_check_statuses.append((cc_model, cc_pk, cc_name, status, status_time))
    return compliance_check_statuses
