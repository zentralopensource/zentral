from unittest.mock import patch
from django.test import TestCase
from zentral.contrib.santa.events import SantaPostflightEvent, SantaPreflightEvent
from zentral.contrib.santa.models import MachineRule, Rule, Target
from zentral.core.incidents.models import Severity
from .utils import SantaSyncClient, force_configuration, force_enrolled_machine, force_rule, new_sha256


class SantaSyncSessionTestCase(TestCase):
    """Drive full sync sessions - preflight, rule download, postflight - against the sync views."""

    maxDiff = None

    # utils

    def force_client(self, batch_size=None, rule_count=0, **kwargs):
        configuration = force_configuration()
        if batch_size is not None:
            configuration.batch_size = batch_size
            configuration.save()
        enrolled_machine = force_enrolled_machine(configuration=configuration, **kwargs)
        targets = [
            force_rule(configuration=configuration,
                       target_type=Target.Type.BINARY,
                       target_identifier=new_sha256()).target
            for _ in range(rule_count)
        ]
        return SantaSyncClient(enrolled_machine), configuration, targets

    def synced_rule_count(self, enrolled_machine):
        """The rules the client confirmed with a postflight"""
        return MachineRule.objects.filter(enrolled_machine=enrolled_machine,
                                          sync_session__isnull=True).count()

    def staged_rule_count(self, enrolled_machine):
        return MachineRule.objects.filter(enrolled_machine=enrolled_machine,
                                          sync_session__isnull=False).count()

    def postflight_events(self, post_event):
        return [call_args.args[0] for call_args in post_event.call_args_list
                if isinstance(call_args.args[0], SantaPostflightEvent)]

    def last_preflight_sync_session(self, post_event):
        events = [call_args.args[0] for call_args in post_event.call_args_list
                  if isinstance(call_args.args[0], SantaPreflightEvent)]
        return events[-1].payload["sync_session"]

    # a full sync converges

    def test_full_sync_client_gets_all_the_rules(self):
        client, _, targets = self.force_client(rule_count=3)
        response = client.sync()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(client.rules), 3)
        self.assertEqual(self.synced_rule_count(client.enrolled_machine), 3)

    def test_full_sync_multiple_batches(self):
        client, _, targets = self.force_client(batch_size=2, rule_count=5)
        response = client.sync()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(client.rules), 5)
        self.assertEqual(self.synced_rule_count(client.enrolled_machine), 5)

    def test_second_sync_sends_nothing_new(self):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        rules = client.rule_download()
        self.assertEqual(rules, [])

    # the reported counts match the ledger

    def test_sync_then_preflight_in_sync(self):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        response = client.preflight()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sync_type"], "NORMAL")
        client.enrolled_machine.refresh_from_db()
        self.assertEqual(client.enrolled_machine.binary_rule_count, 2)
        self.assertTrue(client.enrolled_machine.sync_ok())

    def test_transitive_rules_do_not_break_the_comparison(self):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        client.add_transitive_rule()
        client.add_transitive_rule()
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertEqual(client.enrolled_machine.binary_rule_count, 4)
        self.assertEqual(client.enrolled_machine.transitive_rule_count, 2)
        self.assertTrue(client.enrolled_machine.sync_ok())

    # rule removal

    def test_removed_rule_is_removed_from_the_client(self):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        Rule.objects.filter(configuration=configuration, target=targets[0]).delete()
        client.sync()
        self.assertEqual(len(client.rules), 1)
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())

    # clean sync

    def test_requested_clean_sync_rebuilds_the_client_rules(self):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        response = client.preflight(request_clean_sync=True)
        self.assertEqual(response.json()["sync_type"], "CLEAN")
        rules = client.rule_download()
        self.assertEqual(len(rules), 2)
        client.postflight(rules)
        self.assertEqual(len(client.rules), 2)
        self.assertEqual(self.synced_rule_count(client.enrolled_machine), 2)

    def test_clean_sync_keeps_the_client_transitive_rules(self):
        client, _, targets = self.force_client(rule_count=1)
        client.sync()
        client.add_transitive_rule()
        client.sync(request_clean_sync=True)
        self.assertEqual(len(client.transitive_rules), 1)
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())

    # the sync stage timestamps

    def test_sync_records_the_stage_timestamps(self):
        client, _, targets = self.force_client(rule_count=1)
        self.assertIsNone(client.enrolled_machine.last_preflight_at)
        self.assertIsNone(client.enrolled_machine.last_postflight_at)
        client.sync()
        client.enrolled_machine.refresh_from_db()
        self.assertIsNotNone(client.enrolled_machine.last_preflight_at)
        self.assertIsNotNone(client.enrolled_machine.last_postflight_at)
        self.assertLessEqual(client.enrolled_machine.last_preflight_at,
                             client.enrolled_machine.last_postflight_at)

    def test_interrupted_sync_only_records_the_preflight(self):
        client, _, targets = self.force_client(batch_size=1, rule_count=3)
        client.preflight()
        client.rule_download(max_batches=1)
        client.enrolled_machine.refresh_from_db()
        self.assertIsNotNone(client.enrolled_machine.last_preflight_at)
        # the client never confirmed the run
        self.assertIsNone(client.enrolled_machine.last_postflight_at)

    def test_second_preflight_moves_the_preflight_timestamp_only(self):
        client, _, targets = self.force_client(rule_count=1)
        client.sync()
        client.enrolled_machine.refresh_from_db()
        first_preflight_at = client.enrolled_machine.last_preflight_at
        first_postflight_at = client.enrolled_machine.last_postflight_at
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertGreater(client.enrolled_machine.last_preflight_at, first_preflight_at)
        self.assertEqual(client.enrolled_machine.last_postflight_at, first_postflight_at)

    def test_rule_download_without_preflight_does_not_move_the_timestamps(self):
        client, _, targets = self.force_client(rule_count=1)
        client.rule_download()
        client.enrolled_machine.refresh_from_db()
        self.assertIsNone(client.enrolled_machine.last_preflight_at)
        self.assertIsNone(client.enrolled_machine.last_postflight_at)

    # an interrupted rule download must not be recorded as synced

    def test_interrupted_rule_download_is_not_committed(self):
        client, _, targets = self.force_client(batch_size=2, rule_count=6)
        client.preflight()
        # the download dies after the second batch, the client writes nothing
        self.assertIsNone(client.rule_download(max_batches=2))
        self.assertEqual(len(client.rules), 0)
        # the server must not consider any rule as synced
        self.assertEqual(self.synced_rule_count(client.enrolled_machine), 0)
        self.assertEqual(self.staged_rule_count(client.enrolled_machine), 4)

    def test_sync_recovers_from_a_partial_rule_download(self):
        client, configuration, targets = self.force_client(batch_size=2, rule_count=2)
        client.sync()
        self.assertEqual(len(client.rules), 2)
        # six extra rules, the download dies after the second batch
        for _ in range(6):
            force_rule(configuration=configuration,
                       target_type=Target.Type.BINARY,
                       target_identifier=new_sha256())
        client.preflight()
        client.rule_download(max_batches=2)
        self.assertEqual(len(client.rules), 2)
        # the next sync must send every missing rule
        client.sync()
        self.assertEqual(len(client.rules), 8)
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())

    # an interrupted clean sync must leave both sides untouched

    def test_interrupted_clean_sync_is_done_again(self):
        client, configuration, targets = self.force_client(batch_size=2, rule_count=6)
        configuration.sync_incident_severity = Severity.MAJOR.value
        configuration.save()
        client.sync()
        # a clean sync is requested, but the download dies after the first batch
        client.preflight(request_clean_sync=True)
        client.rule_download(max_batches=1)
        # the client still has its rules
        self.assertEqual(len(client.rules), 6)
        # the ledger of the lost session cannot be restored, so a clean sync is done again.
        # The state of the machine is unknown until it is over, it must not be marked out of sync.
        response = client.preflight()
        self.assertEqual(response.json()["sync_type"], "CLEAN")
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.last_sync_ok)
        rules = client.rule_download()
        client.postflight(rules)
        self.assertEqual(len(client.rules), 6)
        # both sides agree again
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())
        self.assertTrue(client.enrolled_machine.last_sync_ok)

    # a clean sync without any rule to send does not clear the client database

    def test_clean_sync_without_rule_does_not_strand_the_client_rules(self):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        # every rule is removed from the configuration
        Rule.objects.filter(configuration=configuration).delete()
        client.sync(request_clean_sync=True)
        # santa returns before the cleanup when it receives no rule, so the client keeps its rules
        self.assertEqual(len(client.rules), 2)
        # the server must know about them, and remove them during the next sync
        client.sync()
        self.assertEqual(len(client.rules), 0)
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())

    # a machine that agrees with neither hypothesis is out of sync

    def test_reported_rules_matching_neither_hypothesis_is_out_of_sync(self):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        # the client loses one of the rules it confirmed
        client.rules.popitem()
        # two more rules are sent and written, but the postflight never arrives
        for _ in range(2):
            force_rule(configuration=configuration,
                       target_type=Target.Type.BINARY,
                       target_identifier=new_sha256())
        client.preflight()
        self.assertEqual(len(client.rule_download()), 2)
        # 3 reported rules match neither the committed ones nor the session ones
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertEqual(client.enrolled_machine.binary_rule_count, 3)
        self.assertEqual(self.staged_rule_count(client.enrolled_machine), 0)
        self.assertFalse(client.enrolled_machine.sync_ok())

    # a lost postflight must not trigger a full resync

    def test_lost_postflight_is_reconciled_during_the_next_preflight(self):
        client, _, targets = self.force_client(rule_count=3)
        client.preflight()
        rules = client.rule_download()
        self.assertEqual(len(rules), 3)
        # the postflight never reaches the server
        response = client.preflight()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sync_type"], "NORMAL")
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())
        # nothing has to be sent again
        self.assertEqual(client.rule_download(), [])

    # the postflight event reports what the client confirmed

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event(self, post_event):
        client, configuration, targets = self.force_client(rule_count=3)
        client.preflight()
        rules = client.rule_download()
        client.enrolled_machine.refresh_from_db()
        sync_session = client.enrolled_machine.sync_session
        client.postflight(rules, rulesHash="f21eed9991e82ed579458e23ab0d8c60")
        events = self.postflight_events(post_event)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.machine_serial_number, client.serial_number)
        self.assertEqual(
            event.payload,
            {"machine_id": client.machine_id,
             # the client payload is reported as it was received
             "rulesHash": "f21eed9991e82ed579458e23ab0d8c60",
             "syncType": "NORMAL",
             "rules_received": 3,
             "rules_processed": 3,
             "santa_version": client.santa_version,
             "configuration": {"pk": configuration.pk, "name": configuration.name},
             "sync_session": {"id": sync_session,
                              "clean": False,
                              "clean_confirmed": False,
                              "committed": True,
                              "rules_committed": 3,
                              "removals_confirmed": 0,
                              "rules_dropped": 0}}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_missing_counts_are_zero(self, post_event):
        client, _, _ = self.force_client()
        client.sync()
        payload = self.postflight_events(post_event)[-1].payload
        # santa drops the counts set to 0
        self.assertEqual(payload["rules_received"], 0)
        self.assertEqual(payload["rules_processed"], 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_rules_dropped_by_the_client(self, post_event):
        client, _, targets = self.force_client(rule_count=3)
        client.preflight()
        rules = client.rule_download()
        with self.assertLogs("zentral.contrib.santa.views.api", level="ERROR") as cm:
            client.postflight(rules, rules_processed=1)
        payload = self.postflight_events(post_event)[-1].payload
        self.assertEqual(payload["rules_received"], 3)
        self.assertEqual(payload["rules_processed"], 1)
        self.assertIn(
            f"ERROR:zentral.contrib.santa.views.api:Machine {client.serial_number}: "
            "received 3 rules, processed 1",
            cm.output
        )
        # the ledger records them all, the client only says how many it could convert
        self.assertEqual(payload["sync_session"]["rules_committed"], 3)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_bad_counts(self, post_event):
        client, _, _ = self.force_client()
        client.preflight()
        client.rule_download()
        with self.assertLogs("zentral.contrib.santa.views.api", level="ERROR") as cm:
            client.postflight([], rules_received="three", rules_processed=-1)
        payload = self.postflight_events(post_event)[-1].payload
        self.assertEqual(payload["rules_received"], 0)
        self.assertEqual(payload["rules_processed"], 0)
        self.assertIn(
            f"ERROR:zentral.contrib.santa.views.api:Machine {client.serial_number}: "
            "reported rules_received three not an integer",
            cm.output
        )
        self.assertIn(
            f"ERROR:zentral.contrib.santa.views.api:Machine {client.serial_number}: "
            "reported rules_processed -1 negative",
            cm.output
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_confirmed_removal(self, post_event):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        Rule.objects.filter(configuration=configuration, target=targets[0]).delete()
        client.sync()
        payload = self.postflight_events(post_event)[-1].payload
        self.assertEqual(payload["rules_received"], 1)
        self.assertEqual(payload["sync_session"],
                         {"id": payload["sync_session"]["id"],
                          "clean": False,
                          "clean_confirmed": False,
                          "committed": True,
                          # the removal is confirmed, and its ledger row is gone
                          "rules_committed": 0,
                          "removals_confirmed": 1,
                          "rules_dropped": 0})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_clean_session_drops_the_rules_it_did_not_send(self, post_event):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        # one rule is out of scope, a clean session does not send it, not even as a removal
        Rule.objects.filter(configuration=configuration, target=targets[0]).delete()
        client.sync(request_clean_sync=True)
        sync_session = self.postflight_events(post_event)[-1].payload["sync_session"]
        self.assertTrue(sync_session["clean"])
        self.assertTrue(sync_session["clean_confirmed"])
        self.assertEqual(sync_session["rules_committed"], 1)
        self.assertEqual(sync_session["removals_confirmed"], 0)
        # the client rebuilt its database, the rule it was not sent is dropped from the ledger
        self.assertEqual(sync_session["rules_dropped"], 1)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_clean_session_not_confirmed(self, post_event):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        client.preflight(request_clean_sync=True)
        rules = client.rule_download()
        # a client that performs a normal sync instead of the clean one it was answered
        with self.assertLogs("zentral.contrib.santa.views.api", level="ERROR") as cm:
            client.postflight(rules, syncType="NORMAL")
        sync_session = self.postflight_events(post_event)[-1].payload["sync_session"]
        self.assertTrue(sync_session["clean"])
        self.assertFalse(sync_session["clean_confirmed"])
        self.assertEqual(sync_session["rules_dropped"], 0)
        self.assertIn(
            f"ERROR:zentral.contrib.santa.views.api:Machine {client.serial_number}: "
            "sync session clean True, client confirmed sync type NORMAL",
            cm.output
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_clean_session_not_reported(self, post_event):
        client, _, targets = self.force_client(rule_count=2)
        client.sync()
        client.preflight(request_clean_sync=True)
        rules = client.rule_download()
        # a client older than 2025.1 does not report the sync type it performed, so there is
        # nothing to disagree with
        with self.assertNoLogs("zentral.contrib.santa.views.api", level="ERROR"):
            client.postflight(rules, syncType=None)
        sync_session = self.postflight_events(post_event)[-1].payload["sync_session"]
        self.assertTrue(sync_session["clean"])
        self.assertIsNone(sync_session["clean_confirmed"])
        # the session is committed as a normal one
        self.assertEqual(sync_session["rules_dropped"], 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_postflight_event_without_open_session(self, post_event):
        client, _, _ = self.force_client()
        response = client.postflight([])
        self.assertEqual(response.status_code, 200)
        payload = self.postflight_events(post_event)[-1].payload
        self.assertEqual(payload["sync_session"], {"committed": False})

    # the preflight event reports the session it starts, and the one it settled

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_starts_a_session(self, post_event):
        client, _, _ = self.force_client()
        client.preflight()
        client.enrolled_machine.refresh_from_db()
        self.assertEqual(
            self.last_preflight_sync_session(post_event),
            {"id": client.enrolled_machine.sync_session,
             "clean": False,
             "clean_reason": None,
             # the client reports no rule, and no rule was ever synced with it
             "sync_ok": True,
             "previous_session": None}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_clean_sync_requested(self, post_event):
        client, _, _ = self.force_client(rule_count=1)
        client.sync()
        client.preflight(request_clean_sync=True)
        sync_session = self.last_preflight_sync_session(post_event)
        self.assertTrue(sync_session["clean"])
        self.assertEqual(sync_session["clean_reason"], "requested")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_clean_sync_after_a_lost_rule_database(self, post_event):
        client, _, _ = self.force_client(rule_count=2)
        client.sync()
        # the client loses its rule database
        client.rules = {}
        client.preflight()
        sync_session = self.last_preflight_sync_session(post_event)
        self.assertTrue(sync_session["clean"])
        self.assertEqual(sync_session["clean_reason"], "no_reported_rule")
        # the machine is out of sync until the clean session is over
        self.assertFalse(sync_session["sync_ok"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_lost_clean_session_is_discarded(self, post_event):
        client, _, _ = self.force_client(batch_size=2, rule_count=6)
        client.sync()
        client.preflight(request_clean_sync=True)
        # the download dies after the first batch
        client.rule_download(max_batches=1)
        client.enrolled_machine.refresh_from_db()
        lost_session = client.enrolled_machine.sync_session
        client.preflight()
        sync_session = self.last_preflight_sync_session(post_event)
        self.assertEqual(sync_session["clean_reason"], "lost_clean_session")
        # the state of the client cannot be worked out anymore
        self.assertIsNone(sync_session["sync_ok"])
        self.assertEqual(sync_session["previous_session"],
                         {"id": lost_session,
                          "clean": True,
                          "outcome": "discarded",
                          "rules_discarded": 2,
                          "removals_restored": 0})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_lost_postflight_is_committed(self, post_event):
        client, _, _ = self.force_client(rule_count=3)
        client.preflight()
        client.rule_download()
        client.enrolled_machine.refresh_from_db()
        lost_session = client.enrolled_machine.sync_session
        # the postflight never reaches the server
        client.preflight()
        sync_session = self.last_preflight_sync_session(post_event)
        self.assertFalse(sync_session["clean"])
        self.assertTrue(sync_session["sync_ok"])
        self.assertEqual(sync_session["previous_session"],
                         {"id": lost_session,
                          "clean": False,
                          "outcome": "committed",
                          "rules_committed": 3,
                          "removals_confirmed": 0,
                          "rules_dropped": 0})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_interrupted_download_is_discarded(self, post_event):
        client, _, _ = self.force_client(batch_size=1, rule_count=3)
        client.preflight()
        # the download dies after the first batch, the client writes nothing
        self.assertIsNone(client.rule_download(max_batches=1))
        client.preflight()
        sync_session = self.last_preflight_sync_session(post_event)
        self.assertTrue(sync_session["sync_ok"])
        self.assertEqual(sync_session["previous_session"]["outcome"], "discarded")
        self.assertEqual(sync_session["previous_session"]["rules_discarded"], 1)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_preflight_event_restores_an_unconfirmed_removal(self, post_event):
        client, configuration, targets = self.force_client(rule_count=2)
        client.sync()
        Rule.objects.filter(configuration=configuration, target=targets[0]).delete()
        client.preflight()
        # the removal is sent, but the client dies before writing it
        self.assertIsNone(client.rule_download(max_batches=1))
        client.preflight()
        sync_session = self.last_preflight_sync_session(post_event)
        # the client still has the rule, and the removal is sent again during the next session
        self.assertTrue(sync_session["sync_ok"])
        self.assertEqual(sync_session["previous_session"]["outcome"], "discarded")
        self.assertEqual(sync_session["previous_session"]["removals_restored"], 1)
        self.assertEqual(sync_session["previous_session"]["rules_discarded"], 0)
