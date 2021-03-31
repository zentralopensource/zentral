import csv
from datetime import datetime
import json
import logging
import os
import tempfile
from celery import shared_task
from django.core.files import File
from django.core.files.storage import default_storage
from django.utils.text import slugify
import xlsxwriter
from zentral.core.events import event_cls_from_type
from .models import DistributedQuery, FileCarvingSession


logger = logging.getLogger("zentral.contrib.osquery.tasks")


@shared_task(ignore_result=True)
def build_file_carving_session_archive(session_id):
    # get the carve session
    file_carving_session = (FileCarvingSession.objects.select_related("distributed_query", "pack_query")
                                                      .get(pk=session_id))
    if file_carving_session.archive:
        logger.error("Archive already exists for session %s", session_id)
        return

    # build archive file from carve blocks
    archive_size = 0
    tmp_fh, tmp_path = tempfile.mkstemp(suffix="_osquery_file_carving_archive.tar")
    logger.info("Start building archive %s %s", session_id, tmp_path)
    with os.fdopen(tmp_fh, "wb") as f:
        for file_carving_block in file_carving_session.filecarvingblock_set.all().order_by("block_id"):
            for chunk in file_carving_block.file.chunks():
                f.write(chunk)
                archive_size += len(chunk)
    with open(tmp_path, "rb") as f:
        file_carving_session.archive.save("archive.tar", File(f))
    os.unlink(tmp_path)

    # post osquery file carve event
    event_cls = event_cls_from_type("osquery_file_carving")
    event_cls.post_machine_request_payloads(
        file_carving_session.serial_number,
        None, None,
        [{"session_id": session_id,
          "action": "archive",
          "archive": {"name": file_carving_session.get_archive_name(),
                      "size": archive_size,
                      "url": file_carving_session.get_archive_url()}}])


# distributed query result exports


def _export_dqr_to_tmp_csv_file(distributed_query):
    tmp_fh, tmp_fp = tempfile.mkstemp()
    with os.fdopen(tmp_fh, "w", newline='') as tmp_f:
        csv_w = csv.writer(tmp_f)
        columns = distributed_query.result_columns()
        csv_w.writerow(["serial number"] + columns)
        for dqr in distributed_query.distributedqueryresult_set.iterator():
            row = [dqr.serial_number]
            for column in columns:
                row.append(dqr.row.get(column) or "")
            csv_w.writerow(row)
    return tmp_fp


def _export_dqr_to_tmp_ndjson_file(distributed_query):
    tmp_fh, tmp_fp = tempfile.mkstemp()
    with os.fdopen(tmp_fh, "w") as tmp_f:
        for dqr in distributed_query.distributedqueryresult_set.iterator():
            json.dump({"serial_number": dqr.serial_number, "row": dqr.row}, tmp_f)
            tmp_f.write("\n")
    return tmp_fp


def _export_dqr_to_tmp_xlsx_file(distributed_query):
    tmp_fh, tmp_fp = tempfile.mkstemp()
    with os.fdopen(tmp_fh, "wb") as tmp_f:
        workbook = xlsxwriter.Workbook(tmp_f)
        worksheet = workbook.add_worksheet("Results")
        columns = distributed_query.result_columns()
        row_idx = col_idx = 0
        worksheet.write_string(row_idx, col_idx, "serial number")
        for column in columns:
            col_idx += 1
            worksheet.write_string(row_idx, col_idx, column)
        worksheet.freeze_panes(1, 0)
        for dqr in distributed_query.distributedqueryresult_set.iterator():
            row_idx += 1
            col_idx = 0
            worksheet.write_string(row_idx, col_idx, dqr.serial_number)
            for column in columns:
                col_idx += 1
                val = dqr.row.get(column)
                if not val:
                    worksheet.write_blank(row_idx, col_idx, "")
                elif isinstance(val, (int, float)):
                    worksheet.write_number(row_idx, col_idx, val)
                elif isinstance(val, bool):
                    worksheet.write_boolean(row_idx, col_idx, val)
                else:
                    if not isinstance(val, str):
                        val = str(val)
                    worksheet.write_string(row_idx, col_idx, val)
        workbook.close()
    return tmp_fp


def _dqr_export_filename_filepath(distributed_query, extension):
    filename_items = []
    if distributed_query.query:
        filename_items.append(slugify(distributed_query.query.name))
    filename_items.append("run")
    filename_items.append(str(distributed_query.pk))
    filename_items.append("{:%Y-%m-%d_%H-%M-%S}{}".format(datetime.utcnow(), extension))
    filename = "_".join(filename_items)
    filepath = os.path.join("exports", filename)
    return filename, filepath


def _export_distributed_query_results(distributed_query, extension):
    if extension == ".csv":
        content_type = "text/csv"
        exporter = _export_dqr_to_tmp_csv_file
    elif extension == ".ndjson":
        content_type = "application/x-ndjson"
        exporter = _export_dqr_to_tmp_ndjson_file
    elif extension == ".xlsx":
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        exporter = _export_dqr_to_tmp_xlsx_file
    else:
        raise ValueError(f"Unsupported distributed query results export extension: {extension}")

    tmp_filepath = exporter(distributed_query)
    filename, filepath = _dqr_export_filename_filepath(distributed_query, extension)

    with open(tmp_filepath, "rb") as tmp_f:
        default_storage.save(filepath, tmp_f)
    os.unlink(tmp_filepath)

    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": content_type,
            "Content-Length": default_storage.size(filepath),
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    }


@shared_task
def export_distributed_query_results(distributed_query_pk, extension):
    distributed_query = DistributedQuery.objects.get(pk=distributed_query_pk)
    return _export_distributed_query_results(distributed_query, extension)
