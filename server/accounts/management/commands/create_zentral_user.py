import json
import sys
from django.core.management.base import BaseCommand
from django.core.validators import EmailValidator, ValidationError
from accounts.models import APIToken, User
from accounts.password_reset import handler as password_reset_handler


class Command(BaseCommand):
    help = 'Create a Zentral user or service account.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('email')
        parser.add_argument('--service-account', action='store_true',
                            help="Create a service account")
        parser.add_argument('--superuser', action='store_true',
                            help="User has all permissions without explicitly assigning them")
        parser.add_argument('--skip-if-existing', action='store_true')
        parser.add_argument('--with-api-token', action='store_true',
                            help="Generate an API token for the user")
        parser.add_argument('--json', action='store_true',
                            help="Set output mode to 'json'")
        parser.add_argument('--send-reset', action='store_true',
                            help="Send password reset")

    def exit_with_error(self, message, exit_code=1):
        if self.json:
            self.stdout.write(json.dumps({"error": message}, indent=2))
        else:
            self.stderr.write("{}: {}".format("ERROR" if exit_code else "WARNING", message))
        sys.exit(exit_code)

    def print(self, *args):
        if self.json:
            return
        self.stdout.write(" ".join(str(arg) for arg in args))

    def check_options(self):
        if self.service_account:
            if self.superuser:
                self.exit_with_error("A service account cannot be a super user", 5)
            elif self.send_reset:
                self.exit_with_error("A service account cannot receive a password reset", 6)
            self.with_api_token = True

    def check_username(self, username):
        username = username.strip()
        if not username:
            self.exit_with_error("invalid username", 11)
        self.context["username"] = username
        self.username = username

    def check_email(self, email):
        email = email.strip()
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            self.exit_with_error("invalid email address", 12)
        self.context["email"] = email
        self.email = email

    def check_user_conflict(self):
        user = None
        try:
            user = User.objects.get(username=self.username)
        except User.DoesNotExist:
            pass
        else:
            if user.email != self.email:
                self.exit_with_error(
                    f"user {self.username} exists with a different email: {user.email}",
                    13
                )
        try:
            user = User.objects.get(email=self.email)
        except User.DoesNotExist:
            pass
        else:
            if user.username != self.username:
                self.exit_with_error(
                    f"user with email {self.email} exists with a different username: {user.username}",
                    14
                )
        self.user = user

    def create_or_update_user(self):
        created = updated = False
        if not self.user:
            self.user = User.objects.create_user(
                self.username, self.email,
                is_service_account=self.service_account,
                is_superuser=self.superuser
            )
            created = True
            self.print("Superuser" if self.superuser else "User", self.username, self.email, "created")
        else:
            if self.skip_if_existing:
                self.exit_with_error(f"User {self.username} already exists. Nothing to do.", exit_code=0)
            if self.user.is_superuser != self.superuser:
                updated = True
                self.user.is_superuser = self.superuser
                self.user.save()
                if self.superuser:
                    self.print("Existing user", self.username, self.email, "promoted to superuser")
                else:
                    self.print("Existing superuser", self.username, self.email, "demoted")
            else:
                self.print("Superuser" if self.superuser else "User", self.username, self.email, "already exists")
        self.context.update({
            "created": created,
            "updated": updated
        })

    def create_api_token(self):
        self.context["api_token_created"] = False
        if self.with_api_token:
            if APIToken.objects.filter(user=self.user).exists():
                self.print("Existing API token")
            else:
                self.context.update({
                    "api_token": APIToken.objects.update_or_create_for_user(self.user),
                    "api_token_created": True,
                })
                self.print("Created API token:", self.context["api_token"])

    def handle_password_reset(self):
        self.reset_url = None
        if not self.service_account:
            created = self.context["created"]
            if self.send_reset:
                pr_context = password_reset_handler.send_password_reset(self.user, invitation=created)
            else:
                pr_context = password_reset_handler.get_password_reset_context(self.user, invitation=created)
            self.context["password_reset_url"] = pr_context["reset_url"]
            self.print("Password reset:", self.context["password_reset_url"])

    def output_json(self):
        if not self.json:
            return
        self.stdout.write(json.dumps(self.context, indent=2))

    def handle(self, *args, **kwargs):
        self.json = kwargs.get("json", False)
        self.service_account = kwargs.get("service_account", False)
        self.superuser = kwargs.get("superuser", False)
        self.skip_if_existing = kwargs.get("skip_if_existing", False)
        self.with_api_token = kwargs.get("with_api_token", False)
        self.send_reset = kwargs.get("send_reset", False)
        self.context = {
            "service_account": self.service_account,
            "superuser": self.superuser,
        }
        self.check_options()
        self.check_username(kwargs["username"])
        self.check_email(kwargs["email"])
        self.check_user_conflict()
        self.create_or_update_user()
        self.create_api_token()
        self.handle_password_reset()
        self.output_json()
