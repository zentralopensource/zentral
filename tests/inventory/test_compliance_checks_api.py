from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase
from accounts.models import User
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.contrib.inventory.events import JMESPathCheckCreated, JMESPathCheckDeleted, JMESPathCheckUpdated
from zentral.contrib.inventory.models import JMESPathCheck, Tag
from zentral.contrib.inventory.compliance_checks import InventoryJMESPathCheck


class JMESPathCheckAPITests(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            "{}@zentral.io".format(get_random_string(12)),
            get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.token, _ = Token.objects.get_or_create(user=cls.user)

    def setUp(self):
        super().setUp()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    # utils

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def force_compliance_check(self, name=None, jmespath_expression=None, source_name=None, platforms=None, tags=None):
        if name is None:
            name = get_random_string(12)
        cc = ComplianceCheck.objects.create(
            name=name,
            description=get_random_string(12),
            model=InventoryJMESPathCheck.get_model(),
        )
        if jmespath_expression is None:
            jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-4337f02edd29`)"
        if source_name is None:
            source_name = get_random_string(12)
        if platforms is None:
            platforms = ["MACOS"]
        jmespath_check = JMESPathCheck.objects.create(
            compliance_check=cc,
            source_name=source_name,
            platforms=platforms,
            jmespath_expression=jmespath_expression,
        )
        if tags is not None:
            jmespath_check.tags.set(tags)
        return jmespath_check

    # create compliance check

    def test_create_jpcc_unauthorized(self):
        response = self.client.post(reverse('inventory_api:jmespath_checks'), {}, format='json')
        self.assertEqual(response.status_code, 403)

    def test_create_jpcc_name_conflict(self):
        name = get_random_string(12)
        _ = self.force_compliance_check(name=name)
        description = get_random_string(12)
        source_name = get_random_string(12)
        platforms = ["MACOS"]
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)],
                      key=lambda t: t.pk)
        jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-4337f02edd29`)"
        data = {
            "name": name,
            "description": description,
            "source_name": source_name,
            "platforms": platforms,
            "jmespath_expression": jmespath_expression,
            "tags": [t.id for t in tags],
        }
        self.set_permissions('inventory.add_jmespathcheck')
        response = self.client.post(reverse('inventory_api:jmespath_checks'), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['name'], ['A Inventory JMESPath check with this name already exists.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_jpcc(self, post_event):
        name = get_random_string(12)
        description = get_random_string(12)
        source_name = get_random_string(12)
        platforms = ["MACOS"]
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)],
                      key=lambda t: t.pk)
        jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-4337f02edd29`)"
        data = {
            "name": name,
            "description": description,
            "source_name": source_name,
            "platforms": platforms,
            "jmespath_expression": jmespath_expression,
            "tags": [t.id for t in tags],
        }
        self.set_permissions('inventory.add_jmespathcheck')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse('inventory_api:jmespath_checks'), data, format='json')
        self.assertEqual(response.status_code, 201)
        jpcc = JMESPathCheck.objects.get(compliance_check__name=name)
        self.assertEqual(jpcc.compliance_check.description, description)
        self.assertEqual(jpcc.compliance_check.version, 1)
        self.assertEqual(jpcc.source_name, source_name)
        self.assertEqual(jpcc.platforms, platforms)
        self.assertEqual(jpcc.jmespath_expression, jmespath_expression)
        self.assertEqual(list(jpcc.tags.all().order_by("pk")), tags)
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckCreated)
        self.assertEqual(event.payload["pk"], jpcc.compliance_check.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_jpcc_empty_description(self, post_event):
        name = get_random_string(12)
        source_name = get_random_string(12)
        platforms = ["MACOS"]
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)],
                      key=lambda t: t.pk)
        jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-4337f02edd29`)"
        data = {
            "name": name,
            "description": "",
            "source_name": source_name,
            "platforms": platforms,
            "jmespath_expression": jmespath_expression,
            "tags": [t.id for t in tags],
        }
        self.set_permissions('inventory.add_jmespathcheck')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse('inventory_api:jmespath_checks'), data, format='json')
        self.assertEqual(response.status_code, 201)
        jpcc = JMESPathCheck.objects.get(compliance_check__name=name)
        self.assertEqual(jpcc.compliance_check.description, "")
        self.assertEqual(jpcc.compliance_check.version, 1)
        self.assertEqual(jpcc.source_name, source_name)
        self.assertEqual(jpcc.platforms, platforms)
        self.assertEqual(jpcc.jmespath_expression, jmespath_expression)
        self.assertEqual(list(jpcc.tags.all().order_by("pk")), tags)
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckCreated)
        self.assertEqual(event.payload["pk"], jpcc.compliance_check.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_jpcc_missing_description(self, post_event):
        name = get_random_string(12)
        source_name = get_random_string(12)
        platforms = ["MACOS"]
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)],
                      key=lambda t: t.pk)
        jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-4337f02edd29`)"
        data = {
            "name": name,
            "source_name": source_name,
            "platforms": platforms,
            "jmespath_expression": jmespath_expression,
            "tags": [t.id for t in tags],
        }
        self.set_permissions('inventory.add_jmespathcheck')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse('inventory_api:jmespath_checks'), data, format='json')
        self.assertEqual(response.status_code, 201)
        jpcc = JMESPathCheck.objects.get(compliance_check__name=name)
        self.assertEqual(jpcc.compliance_check.description, "")
        self.assertEqual(jpcc.compliance_check.version, 1)
        self.assertEqual(jpcc.source_name, source_name)
        self.assertEqual(jpcc.platforms, platforms)
        self.assertEqual(jpcc.jmespath_expression, jmespath_expression)
        self.assertEqual(list(jpcc.tags.all().order_by("pk")), tags)
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckCreated)
        self.assertEqual(event.payload["pk"], jpcc.compliance_check.pk)

    # get compliance check

    def test_get_jpcc_unauthorized(self):
        jpcc = self.force_compliance_check()
        response = self.client.get(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_jpcc(self):
        tags = [Tag.objects.create(name=get_random_string(12))]
        jpcc = self.force_compliance_check(tags=tags)
        self.set_permissions('inventory.view_jmespathcheck')
        response = self.client.get(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"id": jpcc.pk,
             "name": jpcc.compliance_check.name,
             "description": jpcc.compliance_check.description,
             "version": jpcc.compliance_check.version,
             "source_name": jpcc.source_name,
             "platforms": jpcc.platforms,
             "jmespath_expression": jpcc.jmespath_expression,
             "tags": [t.id for t in tags],  # only works reliably because there is only one tag!
             "created_at": jpcc.created_at.isoformat(),
             "updated_at": jpcc.updated_at.isoformat()}
        )

    # update compliance check

    def test_update_jpcc_unauthorized(self):
        jpcc = self.force_compliance_check()
        response = self.client.put(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)), {}, format='json')
        self.assertEqual(response.status_code, 403)

    def test_update_jpcc_name_conflict(self):
        other_name = get_random_string(12)
        _ = self.force_compliance_check(name=other_name)
        jpcc = self.force_compliance_check()
        data = {
            "name": other_name,
            "description": jpcc.compliance_check.description,
            "source_name": jpcc.source_name,
            "platforms": jpcc.platforms,
            "jmespath_expression": jpcc.jmespath_expression,
            "tags": [t.id for t in jpcc.tags.all()],
        }
        self.set_permissions('inventory.add_jmespathcheck')
        response = self.client.post(reverse('inventory_api:jmespath_checks'), data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['name'], ['A Inventory JMESPath check with this name already exists.'])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_jpcc(self, post_event):
        jpcc = self.force_compliance_check()
        tag = Tag.objects.create(name=get_random_string(12))
        new_jmespath_expression = "contains(profiles[*].uuid, `ca0b2c5d-9bba-416a-a3f4-000000000000`)"
        new_name = get_random_string(12)
        new_description = get_random_string(12)
        new_source_name = get_random_string(12)
        new_platforms = ["LINUX"]
        data = {
            "name": new_name,
            "description": new_description,
            "source_name": new_source_name,
            "platforms": new_platforms,
            "jmespath_expression": new_jmespath_expression,
            "tags": [tag.pk],
        }
        self.set_permissions('inventory.change_jmespathcheck')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.put(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)), data, format='json')
        self.assertEqual(response.status_code, 200)
        jpcc.refresh_from_db()
        self.assertEqual(jpcc.compliance_check.name, new_name)
        self.assertEqual(jpcc.compliance_check.description, new_description)
        self.assertEqual(jpcc.compliance_check.version, 2)
        self.assertEqual(jpcc.source_name, new_source_name)
        self.assertEqual(jpcc.platforms, new_platforms)
        self.assertEqual(jpcc.jmespath_expression, new_jmespath_expression)
        self.assertEqual(list(jpcc.tags.all().order_by("pk")), [tag])
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckUpdated)
        self.assertEqual(event.payload["pk"], jpcc.compliance_check.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_jpcc_same_name_no_platforms_no_tags(self, post_event):
        tags = [Tag.objects.create(name=get_random_string(12))]
        jpcc = self.force_compliance_check(tags=tags)
        data = {
            "name": jpcc.compliance_check.name,
            "description": jpcc.compliance_check.description,
            "source_name": jpcc.source_name,
            "platforms": [],
            "tags": [],
            "jmespath_expression": jpcc.jmespath_expression,
        }
        self.set_permissions('inventory.change_jmespathcheck')
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.put(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)), data, format='json')
        self.assertEqual(response.status_code, 200)
        jpcc.refresh_from_db()
        self.assertEqual(jpcc.platforms, [])
        self.assertEqual(list(jpcc.tags.all().order_by("pk")), [])
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckUpdated)
        self.assertEqual(event.payload["pk"], jpcc.compliance_check.pk)

    # delete compliance check

    def test_delete_jpcc_unauthorized(self):
        jpcc = self.force_compliance_check()
        response = self.client.delete(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_jpcc(self, post_event):
        jpcc = self.force_compliance_check()
        cc_pk = jpcc.compliance_check.pk
        self.set_permissions("inventory.delete_jmespathcheck")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.delete(reverse('inventory_api:jmespath_check', args=(jpcc.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(JMESPathCheck.objects.filter(pk=jpcc.pk).count(), 0)
        # event
        self.assertEqual(len(post_event.call_args.args), 1)
        event = post_event.call_args.args[0]
        self.assertIsInstance(event, JMESPathCheckDeleted)
        self.assertEqual(event.payload["pk"], cc_pk)

    # list compliance check

    def test_list_jpcc_unauthorized(self):
        response = self.client.get(reverse('inventory_api:jmespath_checks'))
        self.assertEqual(response.status_code, 403)

    def test_list_jpcc(self):
        tags = [Tag.objects.create(name=get_random_string(12))]
        jpcc = self.force_compliance_check(tags=tags)
        self.set_permissions('inventory.view_jmespathcheck')
        response = self.client.get(reverse('inventory_api:jmespath_checks'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{"id": jpcc.pk,
              "name": jpcc.compliance_check.name,
              "description": jpcc.compliance_check.description,
              "version": jpcc.compliance_check.version,
              "source_name": jpcc.source_name,
              "platforms": jpcc.platforms,
              "jmespath_expression": jpcc.jmespath_expression,
              "tags": [t.id for t in tags],  # only works reliably because there is only one tag!
              "created_at": jpcc.created_at.isoformat(),
              "updated_at": jpcc.updated_at.isoformat()}]
        )

    def test_list_jpcc_by_name(self):
        tags = [Tag.objects.create(name=get_random_string(12))]
        self.force_compliance_check(tags=tags)
        jpcc = self.force_compliance_check(tags=tags)
        self.set_permissions('inventory.view_jmespathcheck')
        response = self.client.get(reverse('inventory_api:jmespath_checks'), data={"name": jpcc.compliance_check.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{"id": jpcc.pk,
              "name": jpcc.compliance_check.name,
              "description": jpcc.compliance_check.description,
              "version": jpcc.compliance_check.version,
              "source_name": jpcc.source_name,
              "platforms": jpcc.platforms,
              "jmespath_expression": jpcc.jmespath_expression,
              "tags": [t.id for t in tags],  # only works reliably because there is only one tag!
              "created_at": jpcc.created_at.isoformat(),
              "updated_at": jpcc.updated_at.isoformat()}]
        )
