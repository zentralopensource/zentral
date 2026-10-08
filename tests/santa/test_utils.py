from unittest.mock import Mock

from django.db import DataError, connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from zentral.contrib.santa.models import MetaBundle, Target, TargetCounter
from zentral.contrib.santa.utils import create_targets, update_metabundles

from .utils import new_sha256, new_team_id


class SantaUtilsTestCase(TestCase):
    def test_create_targets(self):
        existing_target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
        binary_identifier = new_sha256()
        team_id = new_team_id()
        increments = {"blocked_incr": 1, "collected_incr": 0, "executed_incr": 0}
        targets = create_targets({
            (Target.Type.BINARY, existing_target.identifier): increments,
            (Target.Type.BINARY, binary_identifier): increments,
            (Target.Type.TEAM_ID, team_id): increments,
        })
        self.assertEqual(
            targets,
            {(Target.Type.BINARY, existing_target.identifier): (existing_target, False),
             (Target.Type.BINARY, binary_identifier):
                 (Target.objects.get(type=Target.Type.BINARY, identifier=binary_identifier), True),
             (Target.Type.TEAM_ID, team_id):
                 (Target.objects.get(type=Target.Type.TEAM_ID, identifier=team_id), True)}
        )
        self.assertEqual(Target.objects.count(), 3)
        self.assertEqual(TargetCounter.objects.count(), 0)

    def test_create_targets_one_insert_statement(self):
        increments = {"blocked_incr": 0, "collected_incr": 0, "executed_incr": 1}
        with CaptureQueriesContext(connection) as ctx:
            targets = create_targets({(Target.Type.BINARY, new_sha256()): increments for _ in range(250)})
        self.assertEqual(len(targets), 250)
        self.assertEqual(Target.objects.count(), 250)
        self.assertEqual(len(ctx.captured_queries), 2)

    # update_metabundles

    def test_update_metabundles_nothing_to_link(self):
        update_metabundles()
        self.assertEqual(MetaBundle.objects.count(), 0)

    def test_update_metabundles_error_rolls_back_to_savepoint(self):
        with self.assertRaises(DataError):
            update_metabundles([Mock(pk="yolo")])
        # the transaction of the caller is still usable
        self.assertEqual(Target.objects.count(), 0)
