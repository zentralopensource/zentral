import csv
import os
from celery import shared_task
from django.core.files.storage import default_storage
from django.http import QueryDict
import xlsxwriter
from .forms import MacOSAppSearchForm
from .utils import (MSQuery,
                    export_machine_macos_app_instances as do_export_machine_macos_app_instances,
                    export_machine_program_instances as do_export_machine_program_instances,
                    export_machine_deb_packages as do_export_machine_deb_packages,
                    export_machine_snapshots as do_export_machine_snapshots)


@shared_task
def export_inventory(urlencoded_query_dict, filename):
    msquery = MSQuery(QueryDict(urlencoded_query_dict))
    _, extension = os.path.splitext(filename)
    filepath = os.path.join("exports", filename)
    with default_storage.open(filepath, "wb") as of:
        if extension == ".zip":
            content_type = "application/zip"
            msquery.export_zip(of)
        elif extension == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            msquery.export_xlsx(of)
        else:
            raise ValueError("Unknown file extension '{}'".format(extension))
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }


@shared_task
def export_macos_apps(form_data, filename):
    form = MacOSAppSearchForm(form_data or {}, export=True)
    assert(form.is_valid())
    _, extension = os.path.splitext(filename)
    filepath = os.path.join("exports", filename)
    if extension == ".csv":
        with default_storage.open(filepath, "w") as of:
            content_type = "text/csv"
            writer = csv.writer(of, delimiter=";")
            headers = False
            for app in form.iter_results():
                del app["id"]
                if not headers:
                    writer.writerow(h.replace("_", " ").title() for h in app.keys())
                    headers = True
                else:
                    writer.writerow(str(val) if val is not None else "" for val in app.values())
    elif extension == ".xlsx":
        with default_storage.open(filepath, "wb") as of:
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            workbook = xlsxwriter.Workbook(of)
            worksheet = workbook.add_worksheet("MacOS Apps")
            headers = False
            row_idx = 0
            for app in form.iter_results():
                del app["id"]
                col_idx = 0
                if not headers:
                    for header in app.keys():
                        worksheet.write_string(row_idx, col_idx, header.replace("_", " ").title())
                        col_idx += 1
                    worksheet.freeze_panes(1, 0)
                    headers = True
                else:
                    for k, v in app.items():
                        if k == "machine_count":
                            worksheet.write_number(row_idx, col_idx, v)
                        else:
                            if not v:
                                v = ""
                            worksheet.write_string(row_idx, col_idx, v)
                        col_idx += 1
                row_idx += 1
            workbook.close()
    else:
        raise ValueError("Unknown file extension '{}'".format(extension))
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Disposition": 'attachment; filename="{}"'.format(filename.replace('"', "'")),
        }
    }


@shared_task
def export_machine_macos_app_instances(source_name=None):
    return do_export_machine_macos_app_instances(source_name=source_name)


@shared_task
def export_machine_program_instances(source_name=None):
    return do_export_machine_program_instances(source_name=source_name)


@shared_task
def export_machine_deb_packages(source_name=None):
    return do_export_machine_deb_packages(source_name=source_name)


@shared_task
def export_machine_snapshots(source_name=None):
    return do_export_machine_snapshots(source_name=source_name)
