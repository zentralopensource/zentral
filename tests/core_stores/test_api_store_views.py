from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.core.events.base import AuditEvent
from zentral.core.stores.models import Store
from .utils import force_store


class StoreAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.com".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

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

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    # list stores

    def test_list_stores_unauthorized(self):
        response = self.get(reverse("stores_api:stores"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_stores_permission_denied(self):
        response = self.get(reverse("stores_api:stores"))
        self.assertEqual(response.status_code, 403)

    def test_list_stores(self):
        force_store()
        store = force_store()
        self.set_permissions("stores.view_store")
        response = self.get(reverse("stores_api:stores") + f"?name={store.name}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'admin_console': False,
              'backend': 'HTTP',
              'created_at': store.created_at.isoformat(),
              'description': '',
              'event_filters': {},
              'events_url_authorized_roles': [],
              'http_kwargs': {'concurrency': 1,
                              'endpoint_url': 'https://www.example.com',
                              'max_retries': 3,
                              'password': None,
                              'request_timeout': 120,
                              'username': None,
                              'verify_tls': True},
              'id': str(store.pk),
              'name': store.name,
              'provisioning_uid': None,
              'updated_at': store.updated_at.isoformat()}]
        )

    def test_list_provisioned_store(self):
        store = force_store(provisioned=True)
        self.set_permissions("stores.view_store")
        response = self.get(reverse("stores_api:stores"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            [{'admin_console': False,
              'created_at': store.created_at.isoformat(),
              'description': '',
              'event_filters': {},
              'events_url_authorized_roles': [],
              'id': str(store.pk),
              'name': store.name,
              'provisioning_uid': store.instance.provisioning_uid,
              'updated_at': store.updated_at.isoformat()}]
        )

    # create store

    def test_create_store_unauthorized(self):
        response = self.post(reverse("stores_api:stores"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_store_permission_denied(self):
        response = self.post(reverse("stores_api:stores"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_store_missing_fields(self):
        self.set_permissions("stores.add_store")
        response = self.post(reverse("stores_api:stores"), {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'backend': ['This field is required.'], 'name': ['This field is required.']}
        )

    def test_create_store_unknown_backend(self):
        self.set_permissions("stores.add_store")
        response = self.post(
            reverse("stores_api:stores"),
            {"name": get_random_string(12),
             "backend": "YOLO"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'backend': ['"YOLO" is not a valid choice.']}
        )

    def test_create_http_store_missing_field(self):
        self.set_permissions("stores.add_store")
        response = self.post(
            reverse("stores_api:stores"),
            {"name": get_random_string(12),
             "backend": "HTTP"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'http_kwargs': ['This field is required.']},
        )

    def test_create_http_store_missing_kwargs_field(self):
        self.set_permissions("stores.add_store")
        response = self.post(
            reverse("stores_api:stores"),
            {"name": get_random_string(12),
             "backend": "HTTP",
             "http_kwargs": {}}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'http_kwargs': {'endpoint_url': ['This field is required.']}},
        )

    def test_create_http_store_invalid_event_filters(self):
        self.set_permissions("stores.add_store")
        response = self.post(
            reverse("stores_api:stores"),
            {"name": get_random_string(12),
             "event_filters": {"included_event_filters": []},
             "description": get_random_string(12),
             "backend": "HTTP",
             "http_kwargs": {"endpoint_url": "https://www.example.com/post"}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'event_filters': {
                'non_field_errors': [
                    'Invalid event filters: included_event_filters value is empty'
                ]
            }}
        )

    def test_create_http_store_insufficient_quota(self):
        # max_custom_store_count set to 1 in tests base.json
        force_store()
        self.set_permissions("stores.add_store")
        response = self.post(
            reverse("stores_api:stores"),
            {"name": get_random_string(12),
             "description": get_random_string(12),
             "backend": "HTTP",
             "http_kwargs": {"endpoint_url": "https://www.example.com/post"}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ['Insufficient quota'])

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_store_nones(self, post_event, send_notification):
        self.set_permissions("stores.add_store")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("stores_api:stores"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP",
                 "event_filters": {},
                 "http_kwargs": {
                     "endpoint_url": "https://www.example.com/post",
                     "username": None,
                     "password": None,
                     "headers": [],
                 },
                 "splunk_kwargs": None}
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        store = Store.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'admin_console': False,
             'backend': 'HTTP',
             'created_at': store.created_at.isoformat(),
             'description': description,
             'event_filters': {},
             'events_url_authorized_roles': [],
             'http_kwargs': {'concurrency': 1,
                             'endpoint_url': 'https://www.example.com/post',
                             'headers': [],
                             'max_retries': 3,
                             'password': None,
                             'request_timeout': 120,
                             'username': None,
                             'verify_tls': True},
             'id': str(store.pk),
             'name': name,
             'provisioning_uid': None,
             'updated_at': store.updated_at.isoformat()}
        )
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {'model': 'stores.store',
                        'new_value': {'admin_console': False,
                                      'backend': 'HTTP',
                                      'backend_kwargs': {'concurrency': 1,
                                                         'endpoint_url': 'https://www.example.com/post',
                                                         'headers': [],
                                                         'max_retries': 3,
                                                         'password_hash': None,
                                                         'request_timeout': 120,
                                                         'username': None,
                                                         'verify_tls': True},
                                      'created_at': store.created_at,
                                      'description': description,
                                      'event_filters': {},
                                      'events_url_authorized_roles': [],
                                      'name': name,
                                      'pk': str(store.pk),
                                      'updated_at': store.updated_at},
                        'pk': str(store.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"stores_store": [str(store.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["stores", "zentral"])
        send_notification.assert_called_once_with("stores.store", str(store.pk))

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.setup_store_worker_queue")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_store_min(self, post_event, setup_store_worker_queue, send_notification):
        self.set_permissions("stores.add_store")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("stores_api:stores"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP",
                 "http_kwargs": {"endpoint_url": "https://www.example.com/post"}},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        store = Store.objects.get(name=name)
        self.assertEqual(response.json(), {
            'admin_console': False,
            'backend': 'HTTP',
            'created_at': store.created_at.isoformat(),
            'description': description,
            'event_filters': {},
            'events_url_authorized_roles': [],
            'http_kwargs': {'concurrency': 1,
                            'endpoint_url': 'https://www.example.com/post',
                            'max_retries': 3,
                            'password': None,
                            'request_timeout': 120,
                            'username': None,
                            'verify_tls': True},
            'id': str(store.pk),
            'name': name,
            'provisioning_uid': None,
            'updated_at': store.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {'model': 'stores.store',
                        'pk': str(store.pk),
                        'new_value': {'admin_console': False,
                                      'backend': 'HTTP',
                                      'backend_kwargs': {'concurrency': 1,
                                                         'endpoint_url': 'https://www.example.com/post',
                                                         'max_retries': 3,
                                                         'request_timeout': 120,
                                                         'verify_tls': True},
                                      'created_at': store.created_at,
                                      'description': description,
                                      'event_filters': {},
                                      'events_url_authorized_roles': [],
                                      'name': name,
                                      'pk': str(store.pk),
                                      'updated_at': store.updated_at}}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"stores_store": [str(store.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["stores", "zentral"])
        setup_store_worker_queue.assert_called_once_with(store.get_backend())
        send_notification.assert_called_once_with("stores.store", str(store.pk))

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.setup_store_worker_queue")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_http_store_max(self, post_event, setup_store_worker_queue, send_notification):
        self.set_permissions("stores.add_store")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("stores_api:stores"),
                {"name": name,
                 "description": description,
                 "backend": "HTTP",
                 "event_filters": {
                     "included_event_filters": [{"tags": ["zentral"]}],
                     "excluded_event_filters": [{"event_type": ["zentral_logout"]}],
                 },
                 "events_url_authorized_roles": [self.group.pk],
                 "http_kwargs": {
                     "endpoint_url": "https://www.example.com/post",
                     "username": "yolo",
                     "password": "fomo",
                     "headers": [
                         {"name": "X-Fomo",
                          "value": "Yolo"},
                     ],
                 }},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(callbacks), 1)
        store = Store.objects.get(name=name)
        self.assertEqual(response.json(), {
            'id': str(store.pk),
            'provisioning_uid': None,
            'name': name,
            'description': description,
            'admin_console': False,
            "event_filters": {
                "included_event_filters": [{"tags": ["zentral"]}],
                "excluded_event_filters": [{"event_type": ["zentral_logout"]}],
            },
            "events_url_authorized_roles": [self.group.pk],
            'backend': 'HTTP',
            'http_kwargs': {
                 "endpoint_url": "https://www.example.com/post",
                 "username": "yolo",
                 "password": "fomo",
                 "headers": [
                     {"name": "X-Fomo",
                      "value": "Yolo"},
                 ],
                 "request_timeout": 120,
                 "max_retries": 3,
                 "concurrency": 1,
                 "verify_tls": True,
            },
            'created_at': store.created_at.isoformat(),
            'updated_at': store.updated_at.isoformat(),
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                  "model": "stores.store",
                  "pk": str(store.pk),
                  "new_value": {
                    "pk": str(store.pk),
                    "name": name,
                    "description": description,
                    "admin_console": False,
                    "event_filters": {
                        "included_event_filters": [{"tags": ["zentral"]}],
                        "excluded_event_filters": [{"event_type": ["zentral_logout"]}],
                    },
                    "events_url_authorized_roles": [{"pk": self.group.pk, "name": self.group.name}],
                    "backend": "HTTP",
                    "backend_kwargs": {
                        "endpoint_url": "https://www.example.com/post",
                        "username": "yolo",
                        "password_hash": "48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671",
                        "headers": [
                            {"name": "X-Fomo",
                             "value_hash": "3c7faa49423a3e7c0d33bbeecb185ce7b2bfa2d82b557a090795b420f450eee9"},
                        ],
                        "request_timeout": 120,
                        "max_retries": 3,
                        "concurrency": 1,
                        "verify_tls": True,
                    },
                    "created_at": store.created_at,
                    "updated_at": store.updated_at,
                  }
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"stores_store": [str(store.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["stores", "zentral"])
        setup_store_worker_queue.assert_called_once_with(store.get_backend())
        send_notification.assert_called_once_with("stores.store", str(store.pk))

    # get store

    def test_get_store_unauthorized(self):
        store = force_store()
        response = self.get(reverse("stores_api:store", args=(store.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_store_permission_denied(self):
        store = force_store()
        response = self.get(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_store(self):
        store = force_store()
        response = self.get(reverse("stores_api:store", args=(store.pk,)))
        self.set_permissions("stores.view_store")
        response = self.get(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'admin_console': False,
             'backend': 'HTTP',
             'created_at': store.created_at.isoformat(),
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [],
             'http_kwargs': {'concurrency': 1,
                             'endpoint_url': 'https://www.example.com',
                             'max_retries': 3,
                             'password': None,
                             'request_timeout': 120,
                             'username': None,
                             'verify_tls': True},
             'id': str(store.pk),
             'name': store.name,
             'provisioning_uid': None,
             'updated_at': store.updated_at.isoformat()}
        )

    def test_get_provisioned_store(self):
        store = force_store(provisioned=True)
        response = self.get(reverse("stores_api:store", args=(store.pk,)))
        self.set_permissions("stores.view_store")
        response = self.get(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            data,
            {'admin_console': False,
             'created_at': store.created_at.isoformat(),
             'description': '',
             'event_filters': {},
             'events_url_authorized_roles': [],
             'id': str(store.pk),
             'name': store.name,
             'provisioning_uid': store.instance.provisioning_uid,
             'updated_at': store.updated_at.isoformat()}
        )

    # update store

    def test_update_store_unauthorized(self):
        store = force_store()
        response = self.put(reverse("stores_api:store", args=(store.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_store_permission_denied(self):
        store = force_store()
        self.set_permissions("stores.view_store")
        response = self.put(reverse("stores_api:store", args=(store.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_store_cannot_be_updated(self):
        store = force_store(provisioned=True)
        self.set_permissions("stores.change_store")
        response = self.put(
            reverse("stores_api:store", args=(store.pk,)),
            {"name": get_random_string(12),
             "description": get_random_string(12),
             "backend": "HTTP",
             "http_kwargs": {"endpoint_url": "https://www.example.com/post"}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            ['This store cannot be updated'],
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.setup_store_worker_queue")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_store(self, post_event, setup_store_worker_queue, send_notification):
        store = force_store()
        prev_value = store.instance.serialize_for_event()
        name = get_random_string(12)
        description = get_random_string(12)
        self.set_permissions("stores.change_store")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("stores_api:store", args=(store.pk,)),
                {"name": name,
                 "description": description,
                 "backend": "HTTP",
                 "http_kwargs": {"endpoint_url": "https://www.example.com/post",
                                 "max_retries": 5,
                                 "verify_tls": False}},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        store2 = Store.objects.get(name=name)
        self.assertEqual(store.instance, store2)
        self.assertEqual(response.json(), {
            'id': str(store.pk),
            'provisioning_uid': None,
            'name': name,
            'description': description,
            'admin_console': False,
            'event_filters': {},
            'events_url_authorized_roles': [],
            'backend': 'HTTP',
            'http_kwargs': {
                 "endpoint_url": "https://www.example.com/post",
                 "request_timeout": 120,
                 "max_retries": 5,
                 "concurrency": 1,
                 "username": None,
                 "password": None,
                 "verify_tls": False,
            },
            'created_at': store2.created_at.isoformat(),
            'updated_at': store2.updated_at.isoformat()
        })
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                  "model": "stores.store",
                  "pk": str(store.pk),
                  "prev_value": prev_value,
                  "new_value": {'admin_console': False,
                                'backend': 'HTTP',
                                'backend_kwargs': {'concurrency': 1,
                                                   'endpoint_url': 'https://www.example.com/post',
                                                   'max_retries': 5,
                                                   'request_timeout': 120,
                                                   'verify_tls': False},
                                'created_at': store.created_at,
                                'description': description,
                                'event_filters': {},
                                'events_url_authorized_roles': [],
                                'name': name,
                                'pk': str(store.pk),
                                'updated_at': store2.updated_at}
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"stores_store": [str(store.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["stores", "zentral"])
        setup_store_worker_queue.assert_called_once_with(store)
        send_notification.assert_called_once_with("stores.store", str(store.pk))

    # delete store

    def test_delete_store_unauthorized(self):
        store = force_store()
        response = self.delete(reverse("stores_api:store", args=(store.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_store_permission_denied(self):
        store = force_store()
        self.set_permissions("stores.view_store")
        response = self.delete(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_store_cannot_be_deleted(self):
        store = force_store(provisioned=True)
        self.set_permissions("stores.delete_store")
        response = self.delete(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            ['This store cannot be deleted'],
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.mark_store_worker_queue_for_deletion")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_store(self, post_event, mark_store_worker_queue_for_deletion, send_notification):
        store = force_store()
        prev_pk = store.instance.pk
        prev_value = store.instance.serialize_for_event()
        self.set_permissions("stores.delete_store")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("stores_api:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(len(callbacks), 1)
        self.assertFalse(Store.objects.filter(name=store.name).exists())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                  "model": "stores.store",
                  "pk": str(store.pk),
                  "prev_value": prev_value,
             }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"stores_store": [str(store.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["stores", "zentral"])
        mark_store_worker_queue_for_deletion.assert_called_once()
        self.assertEqual(len(mark_store_worker_queue_for_deletion.call_args.args), 1)
        call_store = mark_store_worker_queue_for_deletion.call_args.args[0]
        # call_store.instance.pk re-hydrated in this test, because the post commit callbacks are executed
        # and RetrieveUpdateDestroyAPIViewWithAudit re-hydrates the instance PK in perform_destroy > on_commit_callback
        self.assertEqual(call_store, store)
        self.assertEqual(call_store.pk, prev_pk)  # pk re-hydrated via instance pk before post commit callbacks
        mark_store_worker_queue_for_deletion.assert_called_once_with(store)
        send_notification.assert_called_once_with("stores.store", str(store.pk))
