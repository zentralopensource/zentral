import time
from django.db import connection
from zentral.conf import get_retention_days
from .declarations import get_target_status_items


__all__ = [
    "apply_status_report",
    "cleanup_status_reports",
    "get_default_status_report_retention_days",
    "get_target_status",
    "split_status_items",
]


# rebuild


def split_status_items(status_items, item_names, prefix=""):
    # the item names are paths in the StatusItems tree, and some items have a dictionary value
    items = {}
    for key, value in status_items.items():
        name = f"{prefix}{key}"
        if name in item_names or not isinstance(value, dict) or not value:
            items[name] = value
        else:
            items.update(split_status_items(value, item_names, f"{name}."))
    return items


def apply_status_report(status, status_report, item_names):
    if status_report.get("FullReport") is True:
        status = {"items": {}, "errors": {}}
    items = status["items"]
    errors = status["errors"]
    for name, value in split_status_items(status_report["StatusItems"], item_names).items():
        errors.pop(name, None)
        if value is None or value == {}:
            items.pop(name, None)
        elif isinstance(value, list) and name in item_names:
            entries = {entry["identifier"]: entry for entry in items.get(name, [])}
            for entry in value:
                if entry.get("_removed"):
                    entries.pop(entry["identifier"], None)
                else:
                    entries[entry["identifier"]] = entry
            items[name] = list(entries.values())
        else:
            items[name] = value
    for error in status_report["Errors"]:
        name = error["StatusItem"]
        items.pop(name, None)
        errors[name] = error.get("Reasons", [])
    return status


def get_target_status(target):
    model, kwargs = target.get_status_report_model_and_kwargs()
    reports = model.objects.filter(**kwargs)
    # without a full report, the first report of the target is the base
    base = reports.filter(latest_full_report=True).first() or reports.order_by("id").first()
    if base is None:
        return
    item_names = set(get_target_status_items(target))
    status = apply_status_report({"items": {}, "errors": {}}, base.data, item_names)
    for report in reports.filter(pk__gt=base.pk).order_by("pk"):
        status = apply_status_report(status, report.data, item_names)
    return status


# cleanup


DELETE_BATCH_SIZE = 1000


STATUS_REPORT_TABLES = (
    ("mdm_devicestatusreport", "enrolled_device_id"),
    ("mdm_userstatusreport", "enrolled_user_id"),
)


# The base of a target is its newest full report received before the max date. The base and the reports after it
# are kept, whatever their age, because the status is rebuilt from them. A target without a base keeps all its
# reports. SKIP LOCKED lets two runs share the work without waiting for each other.
DELETE_STATUS_REPORTS_QUERY = """
WITH batch AS (
    SELECT r.id
    FROM {table} r
    WHERE r.id > %(last_id)s
      AND r.id <= %(max_id)s
      AND r.id < (
          SELECT MAX(f.id)
          FROM {table} f
          WHERE f.{target_column} = r.{target_column}
            AND f.full_report
            AND f.received_at < %(max_date)s
      )
    ORDER BY r.id
    LIMIT %(batch_size)s
    FOR UPDATE OF r SKIP LOCKED
)
DELETE FROM {table} WHERE id IN (SELECT id FROM batch)
RETURNING id
"""


# The highest base of all the targets. Grouped by target, Postgres reads it from the index of the full reports. A
# plain MAX(id) reads the reports backward from the newest one, until it finds one received before the max date.
MAX_BASE_ID_QUERY = """
SELECT MAX(base_id)
FROM (
    SELECT MAX(id) base_id
    FROM {table}
    WHERE full_report AND received_at < %(max_date)s
    GROUP BY {target_column}
) bases
"""


def get_default_status_report_retention_days():
    return get_retention_days("zentral.contrib.mdm", "status_report_retention_days")


def cleanup_status_report_table(cursor, table, target_column, max_date, batch_size):
    rowcount = 0
    # a deleted report has a lower id than its base, so the batches stop at the highest base instead of reading the
    # newer reports to the end of the table
    cursor.execute(MAX_BASE_ID_QUERY.format(table=table, target_column=target_column), {"max_date": max_date})
    max_id = cursor.fetchone()[0]
    if max_id is not None:
        query = DELETE_STATUS_REPORTS_QUERY.format(table=table, target_column=target_column)
        last_id = 0
        while True:
            cursor.execute(query, {"last_id": last_id, "max_id": max_id, "max_date": max_date,
                                   "batch_size": batch_size})
            batch = cursor.fetchall()
            rowcount += len(batch)
            if len(batch) < batch_size:
                break
            last_id = max(row[0] for row in batch)
    cursor.execute(f"SELECT MAX(c) FROM (SELECT COUNT(*) c FROM {table} GROUP BY {target_column}) t")
    max_rows_per_target = cursor.fetchone()[0] or 0
    return rowcount, max_rows_per_target


def cleanup_status_reports(max_date, result_callback, batch_size=DELETE_BATCH_SIZE):
    start_t = time.monotonic()
    with connection.cursor() as cursor:
        for table, target_column in STATUS_REPORT_TABLES:
            table_start_t = time.monotonic()
            rowcount, max_rows_per_target = cleanup_status_report_table(
                cursor, table, target_column, max_date, batch_size
            )
            result_callback(table, {"rowcount": rowcount,
                                    "duration": time.monotonic() - table_start_t,
                                    "max_rows_per_target": max_rows_per_target})
    return time.monotonic() - start_t
