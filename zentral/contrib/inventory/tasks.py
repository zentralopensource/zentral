import csv
from decimal import Decimal
import os
import tempfile
from celery import shared_task
from django.core.files.storage import default_storage
from django.db import connection
from django.http import QueryDict
from django.utils.text import Truncator
import xlsxwriter
from .events import post_cleanup_finished_event, post_cleanup_started_event
from .forms import AndroidAppSearchForm, DebPackageSearchForm, IOSAppSearchForm, MacOSAppSearchForm, ProgramsSearchForm
from .utils import (MSQuery,
                    cleanup_inventory as do_cleanup_inventory, get_cleanup_max_date,
                    do_full_export,
                    export_machine_macos_app_instances as do_export_machine_macos_app_instances,
                    export_machine_android_apps as do_export_machine_android_apps,
                    export_machine_deb_packages as do_export_machine_deb_packages,
                    export_machine_ios_apps as do_export_machine_ios_apps,
                    export_machine_program_instances as do_export_machine_program_instances,
                    export_machine_snapshots as do_export_machine_snapshots)


@shared_task
def cleanup_inventory(days, serialized_event_request):
    max_date = get_cleanup_max_date(days)
    payload = {"days": days, "max_date": max_date}
    post_cleanup_started_event(payload.copy(), serialized_event_request)

    payload["tables"] = {}

    def result_callback(key, val):
        payload["tables"][key] = val

    with connection.cursor() as cursor:
        payload["duration"] = do_cleanup_inventory(cursor, result_callback, max_date)

    post_cleanup_finished_event(payload, serialized_event_request)
    return payload


@shared_task
def export_full_inventory():
    return do_full_export()


@shared_task
def export_inventory(urlencoded_query_dict, filename):
    msquery = MSQuery(QueryDict(urlencoded_query_dict))
    _, extension = os.path.splitext(filename)
    filepath = os.path.join("exports", filename)
    with tempfile.TemporaryFile() as of:
        if extension == ".zip":
            content_type = "application/zip"
            msquery.export_zip(of)
        elif extension == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            msquery.export_xlsx(of)
        else:
            raise ValueError("Unknown file extension '{}'".format(extension))
        default_storage.save(filepath, of)
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }


def export_apps(form_class, form_data, filename):
    form = form_class(form_data or {}, export=True)
    assert form.is_valid()
    _, extension = os.path.splitext(filename)
    filepath = os.path.join("exports", filename)
    headers = list(label for _, label in form.iter_export_headers())
    if extension == ".csv":
        content_type = "text/csv"
        ofh, op = tempfile.mkstemp()
        with os.fdopen(ofh, mode="w", newline="") as of:
            writer = csv.writer(of, delimiter=";")
            writer.writerow(headers)
            for row in form.iter_export_rows():
                writer.writerow(str(val) if val is not None else "" for val in row)
        with open(op, "rb") as of:
            default_storage.save(filepath, of)
        os.unlink(op)
    elif extension == ".xlsx":
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        with tempfile.TemporaryFile() as of:
            workbook = xlsxwriter.Workbook(of)
            worksheet = workbook.add_worksheet(Truncator(form.title).chars(31))
            row_idx = 0
            col_idx = 0
            for label in headers:
                worksheet.write_string(row_idx, col_idx, label)
                col_idx += 1
            worksheet.freeze_panes(1, 0)
            row_idx += 1
            for row in form.iter_export_rows():
                col_idx = 0
                for val in row:
                    if isinstance(val, (int, Decimal)):
                        worksheet.write_number(row_idx, col_idx, val)
                    else:
                        worksheet.write_string(row_idx, col_idx, val or "")
                    col_idx += 1
                row_idx += 1
            workbook.close()
            default_storage.save(filepath, of)
    else:
        raise ValueError(f"Unknown file extension '{extension}'")
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }


@shared_task
def export_android_apps(form_data, filename):
    return export_apps(AndroidAppSearchForm, form_data, filename)


@shared_task
def export_deb_packages(form_data, filename):
    return export_apps(DebPackageSearchForm, form_data, filename)


@shared_task
def export_ios_apps(form_data, filename):
    return export_apps(IOSAppSearchForm, form_data, filename)


@shared_task
def export_macos_apps(form_data, filename):
    return export_apps(MacOSAppSearchForm, form_data, filename)


@shared_task
def export_programs(form_data, filename):
    return export_apps(ProgramsSearchForm, form_data, filename)


@shared_task
def export_machine_macos_app_instances(source_name=None):
    return do_export_machine_macos_app_instances(source_name=source_name)


@shared_task
def export_machine_android_apps(source_name=None):
    return do_export_machine_android_apps(source_name=source_name)


@shared_task
def export_machine_deb_packages(source_name=None):
    return do_export_machine_deb_packages(source_name=source_name)


@shared_task
def export_machine_ios_apps(source_name=None):
    return do_export_machine_ios_apps(source_name=source_name)


@shared_task
def export_machine_program_instances(source_name=None):
    return do_export_machine_program_instances(source_name=source_name)


@shared_task
def export_machine_snapshots(source_name=None):
    return do_export_machine_snapshots(source_name=source_name)
