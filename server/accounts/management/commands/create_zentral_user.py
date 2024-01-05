import json
import sys
from django.core.management.base import BaseCommand
from django.core.validators import EmailValidator, ValidationError
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from accounts.password_reset import handler as password_reset_handler


class Command(BaseCommand):
    help = 'Used to create a Zentral user.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('email')
        parser.add_argument('--skip-if-existing', action='store_true')
        parser.add_argument('--superuser', action='store_true',
                            help="User has all permissions without explicitly assigning them")
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

    def handle(self, *args, **kwargs):
        self.json = kwargs.get("json", False)
        username = kwargs["username"].strip()
        if not username:
            self.exit_with_error("invalid username", 11)
        email = kwargs["email"]
        superuser = kwargs.get("superuser", False)
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            self.exit_with_error("invalid email address", 12)
        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            if user.email != email:
                self.exit_with_error(f"user {username} exists with a different email: {user.email}", 13)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            pass
        else:
            if user.username != username:
                self.exit_with_error(
                    "user with email {} exists with a different username: {}".format(email, user.username),
                    14
                )
        created = updated = False
        if not user:
            user = User.objects.create_user(username, email,
                                            password=get_random_string(1024),
                                            is_superuser=superuser)
            created = True
            self.print("Superuser" if superuser else "User", username, email, "created")
        else:
            if kwargs.get("skip_if_existing"):
                self.exit_with_error(f"User {username} already exists. Nothing to do.", exit_code=0)
            if user.is_superuser != superuser:
                updated = True
                user.is_superuser = superuser
                user.save()
                if superuser:
                    self.print("Existing user", username, email, "promoted to superuser")
                else:
                    self.print("Existing superuser", username, email, "demoted")
            else:
                self.print("Superuser" if user.is_superuser else "User", username, email, "already exists")

        # API Token?
        api_key = None
        api_token_created = False
        if kwargs.get("with_api_token"):
            if APIToken.objects.filter(user=user).exists():
                if not self.json:
                    self.print("Existing API token")
            else:
                api_token_created = True
                api_key = APIToken.objects.update_or_create_for_user(user)
                if not self.json:
                    self.print("Created API token", api_key)
        else:
            api_key = None
            api_token_created = False

        if kwargs.get("send_reset", False):
            pr_context = password_reset_handler.send_password_reset(user, invitation=created)
        else:
            pr_context = password_reset_handler.get_password_reset_context(user, invitation=created)

        if self.json:
            self.stdout.write(json.dumps({
                "superuser": superuser,
                "username": user.username,
                "email": user.email,
                "created": created,
                "updated": updated,
                "api_token": api_key,
                "api_token_created": api_token_created,
                "password_reset_url": pr_context["reset_url"]
            }, indent=2))  # lgtm[py/clear-text-logging-sensitive-data]
        else:
            self.print("Password reset:", pr_context["reset_url"])  # lgtm[py/clear-text-logging-sensitive-data]
