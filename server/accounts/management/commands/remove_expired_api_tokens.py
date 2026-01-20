import json
from datetime import date, timedelta

from accounts.models import APIToken, User
from django.core.management.base import BaseCommand
from django.db import transaction

from zentral.core.events.base import AuditEvent
from zentral.core.queues import queues


class Command(BaseCommand):
    help = "Remove expiried Zentral API tokens."
    seperator = "----------------------"

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="JSON output")
        parser.add_argument(
            "--user-id",
            type=int,
            action="append",
            help="User id: if not specified, expired api tokens for all users are removed",
        )
        parser.add_argument(
            "--after-days",
            type=int,
            default=15,
            help="Number of days since token is expired (Default=15)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            dest="dry_run",
            default=False,
            help="Use the command without deletion. Only list deletable tokens.",
        )

    def write_table(self, data, fields):
        for t in data:
            obj_str = " | ".join(str(getattr(t, f)) for f in fields)
            self.stdout.write(obj_str)

    def write_output(self):
        if self.json:
            output = [
                {"token": t.hashed_key, "expiry": str(t.expiry)}
                for t in self.expired_tokens
            ]
            tokens = json.dumps(output, indent=2)
            self.stdout.write(tokens)
        else:
            self.stdout.write(self.seperator)
            self.stdout.write("Delete API Tokens")
            self.stdout.write(self.seperator)
            self.stdout.write(
                f"Expiration date: {self.expired_date} (days since token expired {self.after_days})"
            )
            self.stdout.write(self.seperator)
            if self.user_id:
                self.stdout.write("Delete tokens for users:")
                self.stdout.write(" | ".join(str(u) for u in self.user_list))
                self.stdout.write(self.seperator)
            if self.expired_tokens:
                self.stdout.write("Tokens marked for removal: ")
                self.write_table(
                    self.expired_tokens, ["hashed_key", "expiry", "user_id"]
                )
            else:
                self.stdout.write("No tokens found")
            self.stdout.write(self.seperator)
            if self.dry_run:
                self.stdout.write("Dry-run: nothing will been removed")
                self.stdout.write(self.seperator)

    def handle(self, *args, **kwargs):
        try:
            self.dry_run = kwargs.get("dry_run")
            self.user_id = kwargs.get("user_id", False)
            self.after_days = kwargs.get("after_days", False)
            self.json = kwargs.get("json", False)

            self.expired_date = date.today() - timedelta(days=self.after_days)
            self.expired_tokens = APIToken.objects.filter(expiry__lt=self.expired_date)
            if self.user_id:
                self.user_list = User.objects.filter(id__in=self.user_id)
                self.expired_tokens = self.expired_tokens.filter(user__in=self.user_id)

            self.write_output()

            if not self.dry_run:
                # remove the tokens
                for token in self.expired_tokens:
                    with transaction.atomic():
                        event = AuditEvent.build(
                            token,
                            action=AuditEvent.Action.DELETED,
                            prev_value=token.serialize_for_event(),
                        )

                        token.delete()

                        def on_commit_callback():
                            event.post()

                        transaction.on_commit(on_commit_callback)
        finally:
            queues.stop()
