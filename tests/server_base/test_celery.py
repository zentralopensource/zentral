from unittest.mock import patch
from django.test import SimpleTestCase
from server.celery import create_task_result_on_publish


class TestZentralCelery(SimpleTestCase):
    @patch("server.celery.logger.error")
    def test_create_task_result_on_publish_unexpected_context(self, logger_error):
        self.assertIsNone(create_task_result_on_publish())
        logger_error.assert_called_once_with("Unexpected calling context")

    @patch("server.celery.logger.error")
    @patch("server.celery.db_result_backend")
    def test_create_task_result_on_publish_could_not_store(self, db_result_backend, logger_error):
        db_result_backend.store_result.side_effect = ValueError
        self.assertIsNone(create_task_result_on_publish(
            sender="zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task",
            headers={
                'task': 'zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task',
                'id': '0b56443a-597f-4492-818e-6e2a4ad45a91'
            },
        ))
        logger_error.assert_called_once_with(
            'Could not store pending task %s result',
            '0b56443a-597f-4492-818e-6e2a4ad45a91',
            exc_info=True,
        )
        db_result_backend.store_result.assert_called_once()
