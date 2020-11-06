import json
import sys
from django.contrib.auth.tokens import default_token_generator
from django.core.management.base import BaseCommand
from django.core.validators import EmailValidator, ValidationError
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework.authtoken.models import Token
from accounts.models import User
from zentral.conf import settings


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

    def exit_with_error(self, message, exit_code=1):
        if self.json:
            print(json.dumps({"error": message}, indent=2))
        else:
            print("ERROR", message)
        sys.exit(exit_code)

    def handle(self, *args, **kwargs):
        self.json = kwargs.get("json", False)
        username = kwargs["username"].strip()
        if not username:
            self.exit_with_error("invalid username")
        email = kwargs["email"]
        superuser = kwargs.get("superuser", False)
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            self.exit_with_error("invalid email address")
        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            if user.email != email:
                self.exit_with_error("user {} exists with a different email: {}".format(username, user.email))
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            pass
        else:
            if user.username != username:
                self.exit_with_error(
                    "user with email {} exists with a different username: {}".format(email, user.username)
                )
        created = updated = False
        if not user:
            user = User.objects.create_user(username, email,
                                            password=get_random_string(1024),
                                            is_superuser=superuser)
            created = True
            if not self.json:
                print("Superuser" if superuser else "User", username, email, "created")
        else:
            if kwargs.get("skip_if_existing"):
                self.exit_with_error("User {} already exists. Nothing to do.".format(username), exit_code=0)
            if user.is_superuser != superuser:
                updated = True
                user.is_superuser = superuser
                user.save()
                if superuser and not self.json:
                    print("Existing user", username, email, "promoted to superuser")
                elif not self.json:
                    print("Existing superuser", username, email, "demoted")
            else:
                print("Superuser" if user.is_superuser else "User", username, email, "already exists")

        # API Token?
        if kwargs.get("with_api_token"):
            api_token, api_token_created = Token.objects.get_or_create(user=user)
            if not self.json:
                print("Created" if api_token_created else "Existing", "API token", api_token.key)
        else:
            api_token = None
            api_token_created = False

        # generate password reset URL
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        if isinstance(uid, bytes):
            uid = uid.decode("ascii")
        token = default_token_generator.make_token(user)
        password_reset_url = "{}{}".format(
            settings["api"]["tls_hostname"],
            reverse('password_reset_confirm', args=(uid, token))
        )

        if self.json:
            print(json.dumps({
                "superuser": superuser,
                "username": user.username,
                "email": user.email,
                "created": created,
                "updated": updated,
                "api_token": api_token.key if api_token else None,
                "api_token_created": api_token_created,
                "password_reset_url": password_reset_url,
            }, indent=2))
        else:
            print("Password reset:", password_reset_url)
