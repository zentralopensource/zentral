import base64
from functools import reduce
import json
import operator
from urllib.parse import urlencode
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from zentral.core.terraform.models import Lock, State
from zentral.core.terraform.api_views import MAX_VERSIONS_PER_STATE
from .utils import build_lock_info, force_state, force_state_version


class TerraformBackendAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _make_request(
        self, method, url,
        data=None, query_params=None,
        auth=True, broken_auth=False,
        username=None, password=None,
    ):
        kwargs = {}
        if data is not None:
            kwargs["data"] = json.dumps(data)
            kwargs["content_type"] = "application/json"
        else:
            kwargs["content_type"] = "text/plain"
        if query_params:
            url += "?" + urlencode(query_params)
        if auth:
            username = username or self.service_account.username
            password = password or self.api_key
            if broken_auth:
                scheme = "Broken"
            else:
                scheme = "BaSIc"
            kwargs["HTTP_AUTHORIZATION"] = "{} {}".format(
                scheme,
                base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            )
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    # backend state GET

    def test_backend_state_get_unauthorized(self):
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)), auth=False)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Unauthorized")

    def test_backend_state_get_broken(self):
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)), broken_auth=True)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Unauthorized")

    def test_backend_state_get_bad_credentials(self):
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)), auth=True, password="Fomo")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Bad credentials")

    def test_backend_state_get_bad_username(self):
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)), auth=True, username="Fomo")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Bad username")

    def test_backend_state_get_no_module_perms_forbidden(self):
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_state_get_bad_module_perm_forbidden(self):
        self.set_permissions("terraform.view_stateversion")
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_state_get_not_found(self):
        self.set_permissions("terraform.view_state")
        response = self.get(reverse("terraform_api:backend_state", args=("yolo",)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"State not found")

    def test_backend_state_get_no_state_version_not_found(self):
        state = force_state()
        self.set_permissions("terraform.view_state")
        response = self.get(reverse("terraform_api:backend_state", args=(state.slug,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b"State version not found")

    def test_backend_state_get_ok(self):
        state_version = force_state_version(data=b"123456789")
        self.set_permissions("terraform.view_state")
        response = self.get(reverse("terraform_api:backend_state", args=(state_version.state.slug,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'123456789')

    # backend state POST

    def test_backend_state_post_no_existing_state_forbidden(self):
        # unexisting state and only change_state permission
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=("yolo",)),
                             data={"un": 1})
        self.assertEqual(response.status_code, 403)

    def test_backend_state_post_missing_permission_forbidden(self):
        state = force_state()  # existing state but no change_state permission
        self.set_permissions("terraform.view_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             data={"un": 1})
        self.assertEqual(response.status_code, 403)

    def test_backend_state_post_no_state_no_lock_ok(self):
        # unexisting state with add_state and change_state permissions
        self.set_permissions("terraform.add_state", "terraform.change_state")
        qs = State.objects.filter(slug="yolo")
        self.assertEqual(qs.count(), 0)
        response = self.post(reverse("terraform_api:backend_state", args=("yolo",)),
                             data={"un": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        self.assertEqual(qs.count(), 1)
        state = qs.first()
        self.assertEqual(state.slug, "yolo")
        self.assertEqual(state.created_by, self.service_account)
        self.assertEqual(state.created_by_username, self.service_account.username)
        self.assertEqual(state.stateversion_set.count(), 1)
        state_version = state.stateversion_set.first()
        self.assertEqual(json.loads(state_version.get_data()), {"un": 1})
        self.assertEqual(state_version.created_by, self.service_account)
        self.assertEqual(state_version.created_by_username, self.service_account.username)

    def test_backend_state_post_state_no_lock_ok(self):
        state = force_state()  # existing state with change_state permission only
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             data={"un": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        state = State.objects.get(slug=state.slug)
        self.assertEqual(state.stateversion_set.count(), 1)
        state_version = state.stateversion_set.first()
        self.assertEqual(json.loads(state_version.get_data()), {"un": 1})

    def test_backend_state_post_lock_id_but_no_lock_ok(self):
        state = force_state()
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             query_params={"ID": str(uuid.uuid4())},
                             data={"un": 1})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        state = State.objects.get(slug=state.slug)
        self.assertEqual(state.stateversion_set.count(), 1)
        state_version = state.stateversion_set.first()
        self.assertEqual(json.loads(state_version.get_data()), {"un": 1})

    def test_backend_state_post_lock_id_conflict(self):
        state = force_state(locked=True)  # locked with a different lock ID
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             query_params={"ID": str(uuid.uuid4())},
                             data={"un": 1})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.content, b"Bad lock ID")

    def test_backend_state_post_lock_id_required(self):
        state = force_state(locked=True)  # locked with a different lock ID
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             # no lock ID in query params
                             data={"un": 1})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.content, b"Lock ID required")

    def test_backend_state_post_lock_id_ok(self):
        state = force_state(locked=True)
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             query_params={"ID": state.lock.uid},
                             data={"un": 42})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        state = State.objects.get(slug=state.slug)
        self.assertEqual(state.stateversion_set.count(), 1)
        state_version = state.stateversion_set.first()
        self.assertEqual(json.loads(state_version.get_data()), {"un": 42})

    def test_backend_state_post_max_versions_ok(self):
        # prepare a state with the maximum number of versions
        state = None
        for i in range(MAX_VERSIONS_PER_STATE):
            state_version = force_state_version(state, data=str(i).encode("ascii"))
            if state is None:
                state = state_version.state
        self.assertEqual(state.stateversion_set.count(), MAX_VERSIONS_PER_STATE)
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_state", args=(state.slug,)),
                             data={"un": 17})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        self.assertEqual(state.stateversion_set.count(), MAX_VERSIONS_PER_STATE)
        self.assertEqual(
            [sv.get_data() for sv in state.stateversion_set.order_by("-pk")],
            [b'{"un": 17}', b'2', b'1']  # b'0' is gone
        )

    # backend state DELETE

    def test_backend_state_delete_no_perm_forbidden(self):
        self.set_permissions("terraform.change_state")
        response = self.delete(reverse("terraform_api:backend_state", args=("yolo",)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_state_delete_no_state_ok(self):
        self.set_permissions("terraform.delete_state")
        response = self.delete(reverse("terraform_api:backend_state", args=("yolo",)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")

    def test_backend_state_delete_state_ok(self):
        state_version = force_state_version()
        self.set_permissions("terraform.delete_state")
        response = self.delete(reverse("terraform_api:backend_state", args=(state_version.state.slug,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")

    # backend lock POST

    def test_backend_lock_post_no_perm_forbidden(self):
        self.set_permissions("terraform.view_state")
        response = self.post(reverse("terraform_api:backend_lock", args=("yolo",)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_lock_post_no_state_no_perm_forbidden(self):
        self.set_permissions("terraform.change_state")  # but not add_state, and no state
        response = self.post(reverse("terraform_api:backend_lock", args=("yolo",)),
                             data=build_lock_info())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_lock_post_could_not_load_body(self):
        state = force_state()
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_lock", args=(state.slug,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.content, b"Bad request")

    def test_backend_lock_post_conflict(self):
        state = force_state(locked=True)
        self.set_permissions("terraform.change_state")
        response = self.post(reverse("terraform_api:backend_lock", args=(state.slug,)),
                             data=build_lock_info())  # not same lock ID
        self.assertEqual(response.status_code, 409)
        response_lock_info = json.loads(response.content)
        self.assertEqual(state.lock.uid, response_lock_info["ID"])
        self.assertEqual(state.lock.info, response_lock_info)

    def test_backend_lock_post_no_state_ok(self):
        self.set_permissions("terraform.add_state", "terraform.change_state")  # no state, but add_state
        lock_info = build_lock_info()
        response = self.post(reverse("terraform_api:backend_lock", args=("yolo",)),
                             data=lock_info)
        self.assertEqual(response.status_code, 200)
        response_lock_info = json.loads(response.content)
        self.assertEqual(response_lock_info["ID"], lock_info["ID"])
        state = State.objects.get(lock__uid=lock_info["ID"])
        self.assertEqual(state.slug, "yolo")
        self.assertEqual(state.created_by, self.service_account)
        self.assertEqual(state.created_by_username, self.service_account.username)
        self.assertEqual(state.stateversion_set.count(), 0)
        self.assertEqual(state.lock.info, response_lock_info)
        self.assertEqual(state.lock.created_by, self.service_account)
        self.assertEqual(state.lock.created_by_username, self.service_account.username)

    def test_backend_lock_post_state_ok(self):
        state = force_state()
        self.set_permissions("terraform.change_state")  # state, so no need for add_state
        lock_info = build_lock_info()
        response = self.post(reverse("terraform_api:backend_lock", args=(state.slug,)),
                             data=lock_info)
        self.assertEqual(response.status_code, 200)
        response_lock_info = json.loads(response.content)
        self.assertEqual(response_lock_info["ID"], lock_info["ID"])
        state2 = State.objects.get(lock__uid=lock_info["ID"])
        self.assertEqual(state2, state)
        self.assertEqual(state2.lock.info, response_lock_info)
        self.assertEqual(state2.lock.created_by, self.service_account)
        self.assertEqual(state2.lock.created_by_username, self.service_account.username)

    # backend lock DELETE

    def test_backend_lock_delete_no_perm_forbidden(self):
        state = force_state(locked=True)
        self.set_permissions("terraform.view_state")
        response = self.delete(reverse("terraform_api:backend_lock", args=(state.slug,)),
                               data=state.lock.info)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Forbidden")

    def test_backend_lock_delete_ok(self):
        state = force_state(locked=True)
        qs = Lock.objects.filter(state=state)
        self.assertEqual(qs.count(), 1)
        self.set_permissions("terraform.delete_state")
        response = self.delete(reverse("terraform_api:backend_lock", args=(state.slug,)),
                               data=state.lock.info)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        self.assertEqual(qs.count(), 0)

    def test_backend_lock_delete_empty_body_ok(self):
        state = force_state(locked=True)
        qs = Lock.objects.filter(state=state)
        self.assertEqual(qs.count(), 1)
        self.set_permissions("terraform.delete_state")
        response = self.delete(reverse("terraform_api:backend_lock", args=(state.slug,)))  # no data, it happens!
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        self.assertEqual(qs.count(), 0)

    def test_backend_lock_delete_nothing_to_do_ok(self):
        state = force_state()
        qs = Lock.objects.filter(state=state)
        self.assertEqual(qs.count(), 0)
        self.set_permissions("terraform.delete_state")
        response = self.delete(reverse("terraform_api:backend_lock", args=(state.slug,)),
                               data=build_lock_info())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")
        self.assertEqual(qs.count(), 0)
