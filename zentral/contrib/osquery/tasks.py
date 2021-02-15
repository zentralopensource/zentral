import logging
import os
import tempfile
from celery import shared_task
from django.core.files import File
from zentral.core.events import event_cls_from_type
from .models import FileCarvingSession


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
