from io import StringIO
import json
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User


class ListUsersManagementCommandsTest(TestCase):
    def test_json_output(self):
        username1 = "a" + get_random_string(12)
        email1 = f"{username1}@example.com"
        user1 = User.objects.create_user(username1, email1, get_random_string(12))
        group1 = Group.objects.create(name=get_random_string(12))
        user1.groups.set([group1])
        username2 = "z" + get_random_string(12)
        email2 = f"{username2}@example.com"
        user2 = User.objects.create_user(username2, email2, get_random_string(12))
        group2 = Group.objects.create(name=get_random_string(12))
        user2.groups.set([group2])
        group3 = Group.objects.create(name=get_random_string(12))
        user2.groups.set([group3])
        out = StringIO()
        call_command('list_users', '--json', '--role', group2.name, '--role', group3.name, stdout=out)
        result = json.loads(out.getvalue())
        self.assertEqual(
            result,
            [{"id": user2.pk,
              "username": username2,
              "email": email2,
              "is_active": True,
              "is_superuser": False,
              "is_remote": False,
              "is_service_account": False,
              "roles": [group3.name]}]
        )

    def test_json_output_all_users(self):
        user = User.objects.create_user("a" + get_random_string(12), get_random_string(12) + "@example.com",
                                        get_random_string(12), is_superuser=True, is_active=False)
        service_account = User.objects.create_user("b" + get_random_string(12),
                                                   get_random_string(12) + "@example.com",
                                                   is_service_account=True)
        remote_user = User.objects.create_user("c" + get_random_string(12), get_random_string(12) + "@example.com",
                                               is_remote=True)
        groups = sorted((Group.objects.create(name=get_random_string(12)) for _ in range(2)), key=lambda g: g.name)
        remote_user.groups.set(groups)
        out = StringIO()
        call_command('list_users', '--json', stdout=out)
        result = {u["username"]: u for u in json.loads(out.getvalue())}
        self.assertEqual(
            result[user.username],
            {"id": user.pk, "username": user.username, "email": user.email,
             "is_active": False, "is_superuser": True, "is_remote": False, "is_service_account": False,
             "roles": []}
        )
        self.assertEqual(
            result[service_account.username],
            {"id": service_account.pk, "username": service_account.username, "email": service_account.email,
             "is_active": True, "is_superuser": False, "is_remote": False, "is_service_account": True,
             "roles": []}
        )
        self.assertEqual(
            result[remote_user.username],
            {"id": remote_user.pk, "username": remote_user.username, "email": remote_user.email,
             "is_active": True, "is_superuser": False, "is_remote": True, "is_service_account": False,
             "roles": [g.name for g in groups]}
        )

    def test_text_output(self):
        username1 = "a" + get_random_string(12)
        email1 = f"{username1}@example.com"
        user1 = User.objects.create_user(username1, email1, get_random_string(12))
        group1 = Group.objects.create(name=get_random_string(12))
        user1.groups.set([group1])
        username2 = "z" + get_random_string(12)
        email2 = f"{username2}@example.com"
        User.objects.create_user(username2, email2, get_random_string(12))
        Group.objects.create(name=get_random_string(12))
        out = StringIO()
        call_command('list_users', stdout=out)
        result = out.getvalue().splitlines()
        self.assertEqual(
            result,
            [email1, email2]
        )
