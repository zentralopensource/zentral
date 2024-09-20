from django.core.management.base import BaseCommand
from django.db import transaction
from realms.models import Realm, RealmUser
from zentral.contrib.santa.models import Configuration, Rule
from zentral.contrib.santa.ballot_box import BallotBox


class Command(BaseCommand):
    help = 'Convert existing Santa rules to ballots'

    def add_arguments(self, parser):
        parser.add_argument("-r", "--realm", help="Realm name")
        parser.add_argument("-u", "--username", help="Realm user username")
        parser.add_argument("-c", "--configuration", help="Name of the Santa configuration", nargs="*")
        parser.add_argument("-d", "--dry-run", help="Dry run", action="store_true")

    def handle(self, *args, **options):
        realm = Realm.objects.get(name=options["realm"])
        realm_user = RealmUser.objects.get(realm=realm, username=options["username"])
        configurations = list(Configuration.objects.filter(name__in=options["configuration"]).order_by("pk"))
        dry_run = options.get("dry_run")
        try:
            with transaction.atomic():
                self.convert_rules(realm_user, configurations, dry_run)
        except Exception:
            self.stderr.write("Rollback database changes")

    def convert_rules(self, realm_user, configurations, dry_run):
        target_votes = {}
        for configuration in configurations:
            for rule in configuration.rule_set.select_related("target").all():
                yes_vote = Rule.Policy(rule.policy) == Rule.Policy.ALLOWLIST
                target_votes.setdefault(rule.target, []).append((configuration, yes_vote))
        rule_qs = Rule.objects.filter(configuration__in=configurations)

        if dry_run:
            self.stdout.write(f"{rule_qs.count()} rules will be deleted")
        else:
            rule_count, _ = rule_qs.delete()
            self.stdout.write(f"{rule_count} rules deleted")

        for target, votes in target_votes.items():
            votes_display = ", ".join(
                "['{}' {}]".format(c, "up" if y else "down")
                for c, y in votes
            )
            target_display = f"{target.type} {target.identifier}"
            ballot_box = BallotBox.for_realm_user(target, realm_user, lock_target=not dry_run, all_configurations=True)
            if dry_run:
                try:
                    ballot_box.verify_votes(votes)
                except Exception:
                    self.stderr.write(f"Invalid votes {votes_display} on target {target_display}")
                else:
                    self.stdout.write(f"Votes {votes_display} on target {target_display} OK")
            else:
                try:
                    ballot_box.cast_votes(votes)
                except Exception:
                    self.stderr.write(f"Could not cast votes {votes_display} on target {target_display}")
                    raise
                else:
                    self.stdout.write(f"Votes {votes_display} on target {target_display} saved")
