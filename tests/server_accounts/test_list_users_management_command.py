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
            [{"username": username2, "email": email2}]
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
