import csv
import os
import tempfile
import zipfile
from celery import shared_task
from django.core.files.storage import default_storage
from django.db import connection, transaction
from django.utils.text import slugify
import xlsxwriter
from .models import Target


def _iter_targets(q, target_type, window_size=2000):
    query, kwargs = Target.objects.search_query(q, target_type)
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(f"DECLARE santa_targets_export_cursor CURSOR FOR {query}", kwargs)
        while True:
            cursor.execute("FETCH %s FROM santa_targets_export_cursor", [window_size])
            results = cursor.fetchall()
            if not results:
                break
            for target_type, sha_256, obj, _, rule_count in results:
                row = [("sha256", sha_256),
                       ("rule count", rule_count)]
                for k, v in sorted(obj.items()):
                    row.append((k.replace("_", " "), v if v is not None else ""))
                yield target_type, row


def _export_targets_zip(iterator, filepath):
    csv_files = {}
    for target_type, row in iterator:
        try:
            _, _, csv_w = csv_files[target_type]
        except KeyError:
            csv_fh, csv_p = tempfile.mkstemp()
            csv_f = os.fdopen(csv_fh, mode="w", newline="")
            csv_w = csv.writer(csv_f)
            csv_files[target_type] = (csv_f, csv_p, csv_w)
            csv_w.writerow(h for h, _ in row)
        csv_w.writerow(v for _, v in row)

    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_a:
        for target_type, (csv_f, csv_p, csv_w) in csv_files.items():
            csv_f.close()
            zip_a.write(csv_p, f"{slugify(target_type)}.csv")
            os.unlink(csv_p)

    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)
    os.unlink(zip_p)


def _export_targets_xlsx(iterator, filepath):
    xlsx_fh, xlsx_p = tempfile.mkstemp()
    with os.fdopen(xlsx_fh, "wb") as f:
        workbook = xlsxwriter.Workbook(f)
        worksheets = {}
        for target_type, row in iterator:
            try:
                worksheet, row_idx = worksheets[target_type]
            except KeyError:
                worksheet = workbook.add_worksheet(target_type.title())
                row_idx = 0
                for col_idx, (h, _) in enumerate(row):
                    worksheet.write_string(row_idx, col_idx, h)
                worksheet.freeze_panes(1, 0)
                row_idx += 1
            for col_idx, (_, v) in enumerate(row):
                if isinstance(v, int):
                    worksheet.write_number(row_idx, col_idx, v)
                else:
                    worksheet.write_string(row_idx, col_idx, v)
            row_idx += 1
            worksheets[target_type] = worksheet, row_idx
        workbook.close()

    with open(xlsx_p, "rb") as xlsx_f:
        default_storage.save(filepath, xlsx_f)
    os.unlink(xlsx_p)


def _export_targets(query, target_type, filename):
    _, extension = os.path.splitext(filename)
    filepath = os.path.join("exports", filename)
    iterator = _iter_targets(query, target_type)
    if extension == ".zip":
        content_type = "application/zip"
        _export_targets_zip(iterator, filepath)
    elif extension == ".xlsx":
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        _export_targets_xlsx(iterator, filepath)
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
def export_targets(query, target_type, filename):
    return _export_targets(query, target_type, filename)
