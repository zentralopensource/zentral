from unittest.mock import patch
from django.test import TestCase
from server.celery import create_task_result_on_publish
from django_celery_results.models import TaskResult
from accounts.models import User, UserTask
from django.utils.crypto import get_random_string


class TestZentralCelery(TestCase):
    @patch("server.celery.logger.error")
    def test_create_task_result_on_publish_unexpected_context(self, logger_error):
        self.assertIsNone(create_task_result_on_publish())
        logger_error.assert_called_once_with("Unexpected calling context")

    @patch("server.celery.logger.error")
    @patch("server.celery.db_result_backend")
    def test_create_task_result_on_publish_unexpected_context_without_body(self, db_result_backend, logger_error):
        db_result_backend.store_result.side_effect = ValueError
        self.assertIsNone(create_task_result_on_publish(
            sender="zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task",
            headers={
                'task': 'zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task',
                'id': '0b56443a-597f-4492-818e-6e2a4ad45a91'
            },
        ))
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
            body=([], {}, {})
        ))
        logger_error.assert_called_once_with(
            'Could not store pending task %s result',
            '0b56443a-597f-4492-818e-6e2a4ad45a91',
            exc_info=True,
        )
        db_result_backend.store_result.assert_called_once()

    @patch("server.celery.logger.error")
    def test_create_task_result_on_publish_could_not_find_user(self, logger_error):
        self.assertIsNone(create_task_result_on_publish(
            sender="zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task",
            headers={
                'task': 'zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task',
                'id': '0b56443a-597f-4492-818e-6e2a4ad45a91'
            },
            body=([], {'task_user': 0}, dict())
        ))
        logger_error.assert_called_once_with(
            'Task %s user %s does not exist',
            '0b56443a-597f-4492-818e-6e2a4ad45a91',
            0,
        )
        self.assertEqual(UserTask.objects.count(), 0)

    @patch("server.celery.db_result_backend")
    def test_create_task_result_on_publish_could_not_find_task_result(self, db_result_backend):
        user = User.objects.create_user(get_random_string(12), "godzilla@zentral.io", get_random_string(12))
        with self.assertRaises(TaskResult.DoesNotExist):
            create_task_result_on_publish(
                sender="zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task",
                headers={
                    'task': 'zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task',
                    'id': '0b56443a-597f-4492-818e-6e2a4ad45a91'
                },
                body=([], {'task_user': user.id}, dict())
            )

    def test_create_task_result_on_publish_and_find_usertask(self):
        user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        header_id = '0b56443a-597f-4492-818e-6e2a4ad45a91'
        self.assertIsNone(create_task_result_on_publish(
            sender="zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task",
            headers={
                'task': 'zentral.contrib.mdm.tasks.sync_dep_virtual_server_devices_task',
                'id': header_id
            },
            body=([], {'task_user': user.id}, dict())
        ))
        task = TaskResult.objects.get(task_id=header_id)
        self.assertEqual(task.usertask.user.id, user.id)

    def test_create_task_result_on_publish_twice_keeps_the_first_usertask(self):
        user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        other_user = User.objects.create_user(get_random_string(12), "mothra@zentral.io", get_random_string(12))
        header_id = '0b56443a-597f-4492-818e-6e2a4ad45a91'
        for task_user in (user, other_user):
            # a retried task is published a second time, with the same task ID
            self.assertIsNone(create_task_result_on_publish(
                sender="zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task",
                headers={
                    'task': 'zentral.contrib.mdm.tasks.assign_dep_virtual_server_default_enrollment_task',
                    'id': header_id
                },
                body=([], {'task_user': task_user.id}, dict())
            ))
        self.assertEqual(UserTask.objects.count(), 1)
        task = TaskResult.objects.get(task_id=header_id)
        self.assertEqual(task.usertask.user, user)
