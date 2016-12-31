import sys
from django.contrib.auth.tokens import default_token_generator
from django.core.management.base import BaseCommand
from django.core.validators import EmailValidator, ValidationError
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from accounts.models import User
from zentral.conf import settings


class Command(BaseCommand):
    help = 'Used to create a Zentral user.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('email')
        parser.add_argument('--superuser', action='store_true',
                            help="user has all permissions without explicitly assigning them")

    def handle(self, *args, **kwargs):
        username = kwargs["username"].strip()
        if not username:
            print("ERROR: invalid username")
            sys.exit(1)
        email = kwargs["email"]
        superuser = kwargs.get("superuser", False)
        email_validator = EmailValidator()
        try:
            email_validator(email)
        except ValidationError:
            print("ERROR: invalid email address")
            sys.exit(1)
        user = None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            if user.email != email:
                print("ERROR: user {} exists with a different email: {}".format(username, user.email))
                sys.exit(1)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            pass
        else:
            if user.username != username:
                print("ERROR: user with email {} exists with a different username: {}".format(email, user.username))
                sys.exit(1)
        if not user:
            user = User.objects.create_user(username, email,
                                            password=get_random_string(1024),
                                            is_superuser=superuser)
            print("{} {} {} created".format("Superuser" if superuser else "User",
                                            username, email))
        else:
            if user.is_superuser != superuser:
                user.is_superuser = superuser
                user.save()
                if superuser:
                    print("Existing user {} {} promoted to superuser".format(username, email))
                else:
                    print("Existing superuser {} {} demoted".format(username, email))
            else:
                print("{} {} {} already exists".format("Superuser" if user.is_superuser else "User",
                                                       username, email))
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        url = reverse('password_reset_confirm', args=(uid, token))
        print("Password reset: {}{}".format(settings["api"]["tls_hostname"], url))
