from string import ascii_lowercase
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.models import Configuration, ScopedClientMode, ScopedPathRegex
from .utils import assert_audit_event, force_configuration

INVALID_CONFIGURATION = "Select a valid choice. That choice is not one of the available choices."
DUPLICATE_NAME = "The fields configuration, name must make a unique set."


class ScopedItemAPITestMixin:
    """The API of one scoped configuration item model.

    The two models share the base, the four PBAC actions and the views, so the tests that only
    exercise the scope, the authorization and the paging are written once here. What belongs to
    one model — the client mode, the policy and the pattern — is in its own test case.
    """
    maxDiff = None

    # to be defined by the subclasses
    model = None
    # the entries one configuration can hold in the list tests
    list_item_count = 5
    list_url_name = None
    detail_url_name = None
    action_suffix = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase / RequestCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "santa_api"

    def _get_api_key(self):
        return self.api_key

    # utils

    def item_data(self, **kwargs):
        raise NotImplementedError

    # the attributes the update serializer requires, because a PUT is a full update
    update_defaults = {"description": "",
                       "serial_numbers": [], "excluded_serial_numbers": [],
                       "primary_users": [], "excluded_primary_users": [],
                       "tags": [], "excluded_tags": []}

    def full_item_data(self, configuration, **kwargs):
        return {"configuration": configuration.pk, **self.update_defaults, **self.item_data(**kwargs)}

    def duplicate_name_data(self, item):
        return self.item_data(name=item.name)

    def force_item(self, configuration, **kwargs):
        tags = kwargs.pop("tags", None)
        excluded_tags = kwargs.pop("excluded_tags", None)
        item = self.model.objects.create(
            configuration=configuration,
            **self.item_data(**kwargs),
        )
        if tags:
            item.tags.set(tags)
        if excluded_tags:
            item.excluded_tags.set(excluded_tags)
        return item

    def list_url(self):
        return reverse(f"santa_api:{self.list_url_name}")

    def detail_url_for_pk(self, pk):
        return reverse(f"santa_api:{self.detail_url_name}", args=(pk,))

    def detail_url(self, item):
        return self.detail_url_for_pk(item.pk)

    def policy(self, *actions, resource="resource"):
        """A policy granting the given actions, on every resource unless one is given."""
        serialized = ", ".join(f'Santa::Action::"{a}{self.action_suffix}"' for a in actions)
        return ("permit ("
                f' principal in Role::"{self.group.pk}",'
                f" action in [{serialized}],"
                f" {resource}"
                ");\n")

    def all_actions_policy(self, resource="resource"):
        return self.policy("create", "view", "update", "delete", resource=resource)

    # list

    def test_list_unauthorized(self):
        response = self.get(self.list_url(), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_without_the_configuration_is_a_400(self):
        self.set_policy(self.all_actions_policy())
        response = self.get(self.list_url())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"configuration_id": ["This field is required."]})

    def test_list_with_a_configuration_that_is_not_a_number(self):
        self.set_policy(self.all_actions_policy())
        response = self.get(self.list_url() + "?configuration_id=yolo")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"configuration_id": [INVALID_CONFIGURATION]})

    def test_list_with_a_configuration_that_does_not_exist_is_a_400(self):
        configuration = force_configuration()
        pk = configuration.pk
        configuration.delete()
        self.set_policy(self.all_actions_policy())
        response = self.get(self.list_url() + f"?configuration_id={pk}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"configuration_id": [INVALID_CONFIGURATION]})

    def test_list(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        self.set_policy(self.all_actions_policy())
        response = self.get(self.list_url() + f"?configuration_id={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], item.pk)

    def test_list_without_a_policy_is_empty_and_not_a_403(self):
        # an entry the caller cannot see reads like an entry that does not exist, so a 403
        # would say that the configuration has entries
        configuration = force_configuration()
        self.force_item(configuration)
        response = self.get(self.list_url() + f"?configuration_id={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"count": 0, "next": None, "previous": None, "results": []})

    def test_list_only_the_entries_of_the_configuration(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.get(self.list_url() + f"?configuration_id={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [item.pk])

    def test_list_only_the_entries_the_policy_allows(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        self.force_item(configuration)
        self.set_policy(self.policy(
            "view", resource=f'resource == Santa::{self.model.__name__}::"{item.pk}"'
        ))
        response = self.get(self.list_url() + f"?configuration_id={configuration.pk}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], [item.pk])

    def test_list_pages_every_entry_once(self):
        configuration = force_configuration()
        # lowercase names sort the same way in python and in postgres
        items = [self.force_item(configuration, name=get_random_string(12, allowed_chars=ascii_lowercase))
                 for _ in range(self.list_item_count)]
        self.set_policy(self.all_actions_policy())
        expected = [i.pk for i in sorted(items, key=lambda i: i.name)]
        base_url = self.list_url() + f"?configuration_id={configuration.pk}"
        response = self.get(base_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["id"] for r in response.json()["results"]], expected)
        url = base_url + f"&limit={self.list_item_count // 2}"
        seen = []
        while url:
            response = self.get(url)
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["count"], len(items))
            seen.extend(r["id"] for r in payload["results"])
            url = payload["next"]
        self.assertEqual(seen, expected)

    def test_list_paginates_the_authorized_entries(self):
        # the decisions are taken before the page is cut, so a page is full of entries the
        # caller can see and not a page with the ones it cannot removed from it
        configuration = force_configuration()
        items = [self.force_item(configuration) for _ in range(self.list_item_count)]
        allowed = items[:self.list_item_count // 2]
        self.set_policy("".join(
            self.policy("view", resource=f'resource == Santa::{self.model.__name__}::"{i.pk}"')
            for i in allowed
        ))
        response = self.get(self.list_url() + f"?configuration_id={configuration.pk}&limit={len(allowed)}")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], len(allowed))
        self.assertIsNone(payload["next"])
        self.assertEqual(sorted(r["id"] for r in payload["results"]),
                         sorted(i.pk for i in allowed))

    # create

    def test_create_unauthorized(self):
        configuration = force_configuration()
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data()},
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_permission_denied(self):
        configuration = force_configuration()
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data()})
        self.assertEqual(response.status_code, 403)

    def test_create_permission_denied_on_another_configuration(self):
        configuration = force_configuration()
        self.set_policy(self.policy(
            "create", resource=f'resource == Santa::Configuration::"{force_configuration().pk}"'
        ))
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data()})
        self.assertEqual(response.status_code, 403)

    def test_create_without_the_configuration_is_a_400(self):
        # the configuration is the resource of the decision, so it is read before the
        # decision is taken and a body without one is a 400
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 400)
        self.assertIn("configuration", response.json())

    def test_create_with_a_configuration_that_does_not_exist_is_a_400(self):
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {"configuration": 2 ** 31 - 1, **self.item_data()})
        self.assertEqual(response.status_code, 400)
        self.assertIn("configuration", response.json())

    def test_create_permission_denied_before_the_rest_of_the_body(self):
        # the item validator reads the stored entries, so it answers after the decision: a
        # caller the engine refuses would otherwise learn from a 400 that a name is taken
        configuration = force_configuration()
        item = self.force_item(configuration)
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data(name=item.name)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create(self, post_event):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_policy(self.all_actions_policy())
        data = {"configuration": configuration.pk, "tags": [tag.pk], **self.item_data()}
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(self.list_url(), data)
        self.assertEqual(response.status_code, 201)
        item = self.model.objects.get(pk=response.json()["id"])
        self.assertEqual(item.configuration, configuration)
        self.assertEqual(list(item.tags.all()), [tag])
        assert_audit_event(self, post_event, "created", item)

    def test_create_a_duplicate_name_is_a_400(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.duplicate_name_data(item)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"non_field_errors": [DUPLICATE_NAME]})

    def test_create_the_same_name_on_another_configuration(self):
        item = self.force_item(force_configuration())
        configuration = force_configuration()
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data(name=item.name)})
        self.assertEqual(response.status_code, 201)

    def test_create_an_excluded_tag_that_is_included(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, "tags": [tag.pk],
                              "excluded_tags": [tag.pk], **self.item_data()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["excluded_tags"], [f"Both included and excluded: {tag}"])

    # retrieve

    def test_retrieve_unauthorized(self):
        item = self.force_item(force_configuration())
        response = self.get(self.detail_url(item), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_retrieve_permission_denied(self):
        item = self.force_item(force_configuration())
        response = self.get(self.detail_url(item))
        self.assertEqual(response.status_code, 403)

    def test_retrieve_permission_denied_on_another_configuration(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy(
            resource=f'resource in Santa::Configuration::"{force_configuration().pk}"'
        ))
        response = self.get(self.detail_url(item))
        self.assertEqual(response.status_code, 403)

    def test_retrieve_an_entry_that_does_not_exist_is_a_404(self):
        item = self.force_item(force_configuration())
        pk = item.pk
        item.delete()
        self.set_policy(self.all_actions_policy())
        response = self.get(self.detail_url_for_pk(pk))
        self.assertEqual(response.status_code, 404)

    def test_retrieve_separates_a_refused_entry_from_one_that_does_not_exist(self):
        # the entry is the resource of the view action, so it is read to build the request and
        # a primary key that is not stored is a 404 before any decision is taken. The list
        # endpoint hides that difference on purpose, the detail endpoint does not: an entry the
        # caller may not see answers 403, and the primary key is all it gives away
        item = self.force_item(force_configuration())
        pk = item.pk
        self.assertEqual(self.get(self.detail_url_for_pk(pk)).status_code, 403)
        item.delete()
        self.assertEqual(self.get(self.detail_url_for_pk(pk)).status_code, 404)

    def test_retrieve(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        self.set_policy(self.all_actions_policy(
            resource=f'resource in Santa::Configuration::"{configuration.pk}"'
        ))
        response = self.get(self.detail_url(item))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], item.pk)
        self.assertEqual(response.json()["configuration"], configuration.pk)

    # update

    def test_update_permission_denied(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.policy("view"))
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update(self, post_event):
        configuration = force_configuration()
        old_tag = Tag.objects.create(name=get_random_string(12))
        item = self.force_item(configuration, tags=[old_tag])
        prev_value = item.serialize_for_event()
        self.set_policy(self.all_actions_policy())
        new_name = get_random_string(12)
        new_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put(self.detail_url(item),
                                self.full_item_data(configuration, name=new_name,
                                                    tags=[new_tag.pk]))
        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(item.name, new_name)
        self.assertEqual(list(item.tags.all()), [new_tag])
        # prev_value is serialized before the write and the new value after it
        payload, _ = assert_audit_event(self, post_event, "updated", item, prev_value=prev_value)
        self.assertEqual([t["pk"] for t in payload["object"]["prev_value"]["tags"]], [old_tag.pk])
        self.assertEqual([t["pk"] for t in payload["object"]["new_value"]["tags"]], [new_tag.pk])

    def test_update_keeps_its_own_name(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration, name=item.name))
        self.assertEqual(response.status_code, 200)

    def test_update_cannot_reparent(self):
        # the decision is taken on the stored entry, so a writable configuration would move an
        # entry to one the caller is not authorized on, and write it there
        configuration = force_configuration()
        item = self.force_item(configuration)
        other_configuration = force_configuration()
        self.set_policy(self.all_actions_policy(
            resource=f'resource in Santa::Configuration::"{configuration.pk}"'
        ))
        response = self.put(self.detail_url(item),
                            self.full_item_data(other_configuration))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["configuration"], ["An entry cannot change configuration"])
        item.refresh_from_db()
        self.assertEqual(item.configuration, configuration)

    def test_update_with_its_own_configuration(self):
        # what the Terraform provider sends on every apply
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration))
        self.assertEqual(response.status_code, 200)

    def test_update_without_the_configuration_is_a_400(self):
        # a non null foreign key with no default: DRF requires it, and nothing exempts it
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        body = self.full_item_data(item.configuration)
        body.pop("configuration")
        response = self.put(self.detail_url(item), body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["configuration"], ["This field is required."])

    # an update is a full update: the body is the state

    def test_update_without_a_scope_attribute_is_a_400(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        body = self.full_item_data(item.configuration, name=item.name)
        body.pop("excluded_tags")
        response = self.put(self.detail_url(item), body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["excluded_tags"], ["This field is required."])

    def test_update_without_the_description(self):
        # no check reads the description with another attribute, so it is not required
        item = self.force_item(force_configuration(), description="kept")
        self.set_policy(self.all_actions_policy())
        body = self.full_item_data(item.configuration, name=item.name)
        body.pop("description")
        response = self.put(self.detail_url(item), body)
        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(item.description, "kept")

    def test_update_replaces_a_scope_attribute(self):
        old_tag = Tag.objects.create(name=get_random_string(12))
        new_tag = Tag.objects.create(name=get_random_string(12))
        item = self.force_item(force_configuration(), tags=[old_tag], serial_numbers=["ABCD"])
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration, name=item.name, tags=[new_tag.pk]))
        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(list(item.tags.all()), [new_tag])
        # the body names them empty, which is what a full update means
        self.assertEqual(item.serial_numbers, [])

    def test_update_excluding_a_tag_it_includes(self):
        tag = Tag.objects.create(name=get_random_string(12))
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration, name=item.name,
                                                tags=[tag.pk], excluded_tags=[tag.pk]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["excluded_tags"], [f"Both included and excluded: {tag}"])

    def test_update_excluding_a_serial_number_it_includes(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration, name=item.name, serial_numbers=["ABCD"],
                                                excluded_serial_numbers=["ABCD"]))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["excluded_serial_numbers"],
                         ["Both included and excluded: ABCD"])

    def test_update_that_moves_a_tag_to_the_exclusions(self):
        tag = Tag.objects.create(name=get_random_string(12))
        item = self.force_item(force_configuration(), tags=[tag])
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(item.configuration, name=item.name, excluded_tags=[tag.pk]))
        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(list(item.tags.all()), [])
        self.assertEqual(list(item.excluded_tags.all()), [tag])

    def test_update_a_name_that_another_entry_has(self):
        configuration = force_configuration()
        item = self.force_item(configuration)
        other_item = self.force_item(configuration)
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(configuration, name=other_item.name))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"non_field_errors": [DUPLICATE_NAME]})

    def test_patch_is_a_405(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.all_actions_policy())
        response = self.client.patch(
            self.detail_url(item), {"name": get_random_string(12)},
            content_type="application/json", HTTP_AUTHORIZATION=f"Token {self.api_key}",
        )
        self.assertEqual(response.status_code, 405)

    # delete

    def test_delete_permission_denied(self):
        item = self.force_item(force_configuration())
        self.set_policy(self.policy("view", "update"))
        response = self.delete(self.detail_url(item))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete(self, post_event):
        item = self.force_item(force_configuration())
        prev_value = item.serialize_for_event()
        self.set_policy(self.all_actions_policy())
        with self.captureOnCommitCallbacks(execute=True):
            response = self.delete(self.detail_url(item))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.model.objects.filter(pk=item.pk).count(), 0)
        assert_audit_event(self, post_event, "deleted", item, prev_value=prev_value)


class SantaAPIScopedClientModeTestCase(ScopedItemAPITestMixin, TestCase, LoginCase, RequestCase):
    model = ScopedClientMode
    list_url_name = "scoped_client_modes"
    detail_url_name = "scoped_client_mode"
    action_suffix = "ScopedClientMode"
    update_defaults = dict(ScopedItemAPITestMixin.update_defaults,
                           event_detail_source=ScopedClientMode.EventDetailSource.INHERIT,
                           event_detail_url="", event_detail_text="")

    # one entry per mode: a configuration holds a Lockdown entry and a Monitor entry at most
    list_item_count = 2

    def item_data(self, **kwargs):
        data = {"name": get_random_string(12),
                "client_mode": Configuration.LOCKDOWN_MODE}
        data.update(kwargs)
        return data

    def duplicate_name_data(self, item):
        # only the name collides: the other mode is free
        return self.item_data(name=item.name, client_mode=Configuration.MONITOR_MODE)

    def force_item(self, configuration, **kwargs):
        if "client_mode" not in kwargs and self.model.objects.filter(
            configuration=configuration, client_mode=Configuration.LOCKDOWN_MODE
        ).exists():
            kwargs["client_mode"] = Configuration.MONITOR_MODE
        return super().force_item(configuration, **kwargs)

    def test_create_a_second_entry_with_the_same_mode_is_a_400(self):
        configuration = force_configuration()
        self.force_item(configuration)
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {"configuration": configuration.pk, **self.item_data()})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"non_field_errors": ["The fields configuration, client_mode must make a unique set."]})

    def test_create_the_other_mode(self):
        configuration = force_configuration()
        self.force_item(configuration)
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {"configuration": configuration.pk,
                                               **self.item_data(client_mode=Configuration.MONITOR_MODE)})
        self.assertEqual(response.status_code, 201)

    def test_create_a_custom_event_detail_without_a_url(self):
        configuration = force_configuration()
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {
            "configuration": configuration.pk,
            "event_detail_source": ScopedClientMode.EventDetailSource.CUSTOM,
            **self.item_data(),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["event_detail_url"], ["This field is required"])

    def test_update_that_clears_the_url_of_a_custom_event_detail(self):
        configuration = force_configuration()
        item = self.force_item(configuration,
                               event_detail_source=ScopedClientMode.EventDetailSource.CUSTOM,
                               event_detail_url="https://www.example.com/santa")
        self.set_policy(self.all_actions_policy())
        response = self.put(self.detail_url(item),
                            self.full_item_data(
                                item.configuration, name=item.name,
                                event_detail_source=ScopedClientMode.EventDetailSource.CUSTOM,
                            ))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["event_detail_url"], ["This field is required"])

    def test_update_replaces_an_event_detail_source_that_became_invalid(self):
        # the voting realm of the configuration can be cleared after the entry is written. The
        # body is the state, so the entry is edited by naming another source, and not frozen
        configuration = force_configuration()
        item = self.force_item(configuration)
        ScopedClientMode.objects.filter(pk=item.pk).update(
            event_detail_source=ScopedClientMode.EventDetailSource.VOTING_PORTAL
        )
        self.set_policy(self.all_actions_policy())
        new_name = get_random_string(12)
        response = self.put(self.detail_url(item), self.full_item_data(item.configuration, name=new_name))
        self.assertEqual(response.status_code, 200)
        item.refresh_from_db()
        self.assertEqual(item.name, new_name)
        self.assertEqual(item.event_detail_source, ScopedClientMode.EventDetailSource.INHERIT)

    def test_create_a_voting_portal_event_detail_without_a_realm(self):
        configuration = force_configuration()
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(), {
            "configuration": configuration.pk,
            "event_detail_source": ScopedClientMode.EventDetailSource.VOTING_PORTAL,
            **self.item_data(),
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["event_detail_source"],
                         ["The configuration has no voting realm with the user portal enabled"])


class SantaAPIScopedPathRegexTestCase(ScopedItemAPITestMixin, TestCase, LoginCase, RequestCase):
    model = ScopedPathRegex
    list_url_name = "scoped_path_regexes"
    detail_url_name = "scoped_path_regex"
    action_suffix = "ScopedPathRegex"

    def test_create_a_pattern_longer_than_512_characters_is_a_400(self):
        configuration = force_configuration()
        self.set_policy(self.all_actions_policy())
        response = self.post(self.list_url(),
                             {"configuration": configuration.pk, **self.item_data(regex="/a/" + "b" * 510)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"regex": ["Ensure this field has no more than 512 characters."]})

    def item_data(self, **kwargs):
        data = {"name": get_random_string(12),
                "policy": ScopedPathRegex.Policy.ALLOW,
                "regex": f"/Library/Example/{get_random_string(8)}/"}
        data.update(kwargs)
        return data

    def post_regex(self, regex):
        configuration = force_configuration()
        self.set_policy(self.all_actions_policy())
        return self.post(self.list_url(),
                         {"configuration": configuration.pk, **self.item_data(regex=regex)})

    def test_create_a_pattern_that_does_not_compile(self):
        response = self.post_regex("/Library/[")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid regex:", response.json()["regex"][0])

    def test_create_a_pattern_with_a_capture_group(self):
        response = self.post_regex("/Library/(Example)/")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["regex"],
                         ["Capture groups are not allowed, use a non capturing group: (?:abc)"])

    def test_create_a_pattern_with_unscoped_inline_flags(self):
        response = self.post_regex("(?i)/library/")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["regex"],
                         ["Scoped inline flags are required, for example (?i:abc)"])

    def test_create_a_pattern_that_matches_an_empty_path(self):
        response = self.post_regex(".*")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["regex"],
            ["This pattern matches an empty path, so it matches every path. Use .+ and not .*"]
        )
