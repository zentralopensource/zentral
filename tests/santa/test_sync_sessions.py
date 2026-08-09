from django.test import TestCase
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
        self.assertEqual(response.json()["sync_type"], "normal")
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
        self.assertEqual(response.json()["sync_type"], "clean")
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
        self.assertEqual(response.json()["sync_type"], "clean")
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
        self.assertEqual(response.json()["sync_type"], "normal")
        client.enrolled_machine.refresh_from_db()
        self.assertTrue(client.enrolled_machine.sync_ok())
        # nothing has to be sent again
        self.assertEqual(client.rule_download(), [])
