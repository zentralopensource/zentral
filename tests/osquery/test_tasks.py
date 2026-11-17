from unittest.mock import patch
import os
import tempfile
import uuid
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.conf import settings
from zentral.contrib.osquery.events import OsqueryFileCarvingEvent
from zentral.contrib.osquery.models import (DistributedQuery, DistributedQueryResult,
                                            FileCarvingBlock, FileCarvingSession, Query,
                                            file_carving_session_archive_path)
from zentral.contrib.osquery.tasks import build_file_carving_session_archive, export_distributed_query_results
from zentral.utils.time import naive_utcnow


class OsqueryTasksTest(TestCase):
    def _force_distributed_query_with_result(self):
        query = Query.objects.create(name=get_random_string(12), sql="select * from osquery_schedule;")
        distributed_query = DistributedQuery.objects.create(
            query=query,
            query_version=query.version,
            sql=query.sql,
            valid_from=naive_utcnow(),
        )
        DistributedQueryResult.objects.create(
            distributed_query=distributed_query,
            serial_number=get_random_string(12),
            # a string, a number, an empty value and a non-scalar value to
            # exercise the xlsx cell-type branches
            row={"name": "osqueryd", "interval": 60, "path": "", "args": ["--flag"]},
        )
        return distributed_query

    def test_export_distributed_query_results_xlsx(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".xlsx")
        self.assertTrue(result["filepath"].endswith(".xlsx"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(
            result["headers"]["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    def test_export_distributed_query_results_csv(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".csv")
        self.assertTrue(result["filepath"].endswith(".csv"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(result["headers"]["Content-Type"], "text/csv")

    def test_export_distributed_query_results_ndjson(self):
        distributed_query = self._force_distributed_query_with_result()
        result = export_distributed_query_results(distributed_query.pk, ".ndjson")
        self.assertTrue(result["filepath"].endswith(".ndjson"))
        self.assertTrue(default_storage.exists(result["filepath"]))
        self.assertEqual(result["headers"]["Content-Type"], "application/x-ndjson")

    def test_export_distributed_query_results_unsupported_extension(self):
        distributed_query = self._force_distributed_query_with_result()
        with self.assertRaises(ValueError):
            export_distributed_query_results(distributed_query.pk, ".yolo")

    # file carving session archive

    def _force_file_carving_session(self):
        fcs = FileCarvingSession.objects.create(
            id=uuid.uuid4(),
            serial_number=get_random_string(12),
            carve_guid=uuid.uuid4(),
            carve_size=11,
            block_size=8,
            block_count=2,
        )
        # saved out of order, to check that the archive follows the block IDs
        for block_id, content in ((1, b"LOC"), (0, b"YOLOFOMO")):
            fcb = FileCarvingBlock(file_carving_session=fcs, block_id=block_id)
            fcb.file.save(f"{block_id}", ContentFile(content))
            self.addCleanup(default_storage.delete, fcb.file.name)
        self.addCleanup(default_storage.delete, file_carving_session_archive_path(fcs, "archive.tar"))
        return fcs

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_build_file_carving_session_archive(self, post_event):
        fcs = self._force_file_carving_session()
        build_file_carving_session_archive(str(fcs.pk))
        fcs.refresh_from_db()
        with fcs.archive.open("rb") as f:
            self.assertEqual(f.read(), b"YOLOFOMOLOC")
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, OsqueryFileCarvingEvent)
        self.assertEqual(
            event.payload,
            {"session_id": str(fcs.pk),
             "action": "archive",
             "archive": {"name": f"{fcs.pk}_{fcs.serial_number}.tar",
                         "size": 11,
                         "url": f"https://{settings['api']['fqdn']}"
                                f"/osquery/file_carving_sessions/{fcs.pk}/download/"}}
        )
        metadata = event.serialize()["_zentral"]
        self.assertEqual(metadata["machine_serial_number"], fcs.serial_number)
        self.assertNotIn("request", metadata)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_build_file_carving_session_archive_error(self, post_event):
        fcs = self._force_file_carving_session()
        real_mkstemp = tempfile.mkstemp
        # a block read error leaves a partial temporary file, a save error a complete one
        for failing_method in ("chunks", "save"):
            with self.subTest(failing_method=failing_method):
                tmp_paths = []

                def mkstemp(*args, **kwargs):
                    tmp_fh, tmp_path = real_mkstemp(*args, **kwargs)
                    tmp_paths.append(tmp_path)
                    return tmp_fh, tmp_path

                with patch("zentral.contrib.osquery.tasks.tempfile.mkstemp", side_effect=mkstemp), \
                     patch(f"django.db.models.fields.files.FieldFile.{failing_method}", side_effect=OSError("yolo")):
                    with self.assertRaises(OSError):
                        build_file_carving_session_archive(str(fcs.pk))
                self.assertEqual(len(tmp_paths), 1)
                self.assertFalse(os.path.exists(tmp_paths[0]))
        fcs.refresh_from_db()
        self.assertFalse(fcs.archive)
        post_event.assert_not_called()
