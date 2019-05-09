import logging
import os
import tempfile
from celery import shared_task
from django.core.files import File
from zentral.core.events import event_cls_from_type
from .models import CarveSession


logger = logging.getLogger("zentral.contrib.osquery.tasks")


@shared_task(ignore_result=True)
def build_carve_session_archive(session_id):
    # get the carve session
    carve_session = CarveSession.objects.get(session_id=session_id)
    if carve_session.archive:
        logger.error("Archive already exists for session %s", session_id)
        return

    # build archive file from carve blocks
    archive_size = 0
    tmp_fh, tmp_path = tempfile.mkstemp(suffix="_osquery_file_carve_archive.tar")
    logger.info("Start building archive %s %s", session_id, tmp_path)
    with os.fdopen(tmp_fh, "wb") as f:
        for carve_block in carve_session.carveblock_set.all().order_by("block_id"):
            for chunk in carve_block.file.chunks():
                f.write(chunk)
                archive_size += len(chunk)
    with open(tmp_path, "rb") as f:
        carve_session.archive.save("archive.tar", File(f))
    os.unlink(tmp_path)

    # post osquery file carve event
    event_cls = event_cls_from_type("osquery_file_carve")
    event_cls.post_machine_request_payloads(
        carve_session.machine_serial_number,
        None, None,
        [{"probe": {"id": carve_session.probe_source.id,
                    "name": carve_session.probe_source.name},
          "session_id": carve_session.session_id,
          "action": "archive",
          "archive": {"name": carve_session.get_archive_name(),
                      "size": archive_size,
                      "url": carve_session.get_archive_url()}}])
