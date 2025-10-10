import datetime
from unittest.mock import patch, Mock
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.apps_books import (AppsBooksClient,
                                            AppsBooksAPIError, FetchedDataUpdatedError, MDMConflictError,
                                            location_cache, LocationCache)
from zentral.contrib.mdm.models import Location


class MDMAppsBooksClientTestCase(TestCase):
    @patch("zentral.contrib.mdm.apps_books.requests.Session")
    def _get_client(self, responses, with_location, Session):
        if not isinstance(responses, list):
            responses = [responses]
        resp = Mock()
        resp.json.side_effect = responses
        resp.json.status_code = 200
        session = Mock()
        session.headers = {}
        session.get.return_value = resp
        session.post.return_value = resp
        Session.return_value = session
        location = None
        if with_location:
            location = Location(
                server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
                server_token_expiration_date=datetime.date(2050, 1, 1),
                organization_name=get_random_string(12),
                country_code="DE",
                library_uid=str(uuid.uuid4()),
                name=get_random_string(12),
                platform="enterprisestore",
                website_url="https://business.apple.com",
                mdm_info_id=uuid.UUID('34d87460-aae8-45bb-ae1b-575d5fc91f9b')
            )
            location.set_notification_auth_token()
            location.save()
            location.set_server_token(get_random_string(12))
            location.save()
        return AppsBooksClient(
            location.get_server_token() if location else get_random_string(12),
            str(location.mdm_info_id) if location else None,
            location.name if location else None,
            "enterprisestore",
            location
        ), location

    # make_request

    def test_make_request_ok(self):
        client, _ = self._get_client({"ok": True}, False)
        self.assertEqual(client.make_request("/yolo"), {"ok": True})

    def test_invalid_token_no_location_exception(self):
        client, _ = self._get_client({"errorNumber": 9622}, False)
        with self.assertRaises(AppsBooksAPIError) as cm:
            client.make_request("/yolo")
        self.assertEqual(cm.exception.args[0], "Invalid server token")

    def test_invalid_token_location_retry(self):
        client, location = self._get_client([{"errorNumber": 9622}, {"ok": True}], True)
        updated_token = get_random_string(12)
        location.set_server_token(updated_token)
        location.save()
        self.assertEqual(client.make_request("/yolo"), {"ok": True})
        self.assertEqual(client.session.headers["Authorization"], f"Bearer {updated_token}")

    def test_other_error(self):
        client, _ = self._get_client({"errorNumber": 123}, False)
        with self.assertRaises(AppsBooksAPIError) as cm:
            client.make_request("/yolo")
        self.assertEqual(cm.exception.args[0], "Error 123")

    def test_mdm_conflict_error(self):
        client, location = self._get_client({"mdmInfo": {"id": str(uuid.uuid4())}}, True)
        with self.assertRaises(MDMConflictError) as cm:
            client.make_request("/yolo", verify_mdm_info=True)
        self.assertEqual(cm.exception.args[0], f"Location {location.name}: mdmInfo mismatch")

    def test_mdm_no_conflict(self):
        client, location = self._get_client({"mdmInfo": {"id": "34d87460-aae8-45bb-ae1b-575d5fc91f9b"}}, True)
        self.assertEqual(client.make_request("/yolo"), {"mdmInfo": {"id": "34d87460-aae8-45bb-ae1b-575d5fc91f9b"}})

    # get_client_config

    def test_get_client_config_conflict(self):
        client, location = self._get_client({"mdmInfo": {"id": str(uuid.uuid4())}}, True)
        with self.assertRaises(MDMConflictError) as cm:
            client.get_client_config()
        self.assertEqual(cm.exception.args[0], f"Location {location.name}: mdmInfo mismatch")

    def test_get_client_config_ok(self):
        client, _ = self._get_client({"mdmInfo": {"id": "34d87460-aae8-45bb-ae1b-575d5fc91f9b"}}, True)
        self.assertEqual(client.get_client_config(), {"mdmInfo": {"id": "34d87460-aae8-45bb-ae1b-575d5fc91f9b"}})

    # update_client_config

    def test_update_client_config(self):
        client, _ = self._get_client({"ok": True}, True)
        client.update_client_config(get_random_string(12))

    # get_service_config

    def test_get_service_config(self):
        client, _ = self._get_client({"ok": True}, True)
        self.assertEqual(client.get_service_config(), {"ok": True})
        self.assertEqual(len(client.session.get.call_args_list), 1)
        args, kwargs = client.session.get.call_args_list[0]
        self.assertEqual(args, ('https://vpp.itunes.apple.com/mdm/v2/service/config',))
        # second call cached
        self.assertEqual(client.get_service_config(), {"ok": True})
        self.assertEqual(len(client.session.get.call_args_list), 1)

    # get_asset

    def test_get_asset_ok(self):
        client, _ = self._get_client({"assets": [{"ok": True}]}, True)
        self.assertEqual(client.get_asset("yolo", "fomo"), {"ok": True})
        self.assertEqual(len(client.session.get.call_args_list), 1)
        args, kwargs = client.session.get.call_args_list[0]
        self.assertEqual(args, ("https://vpp.itunes.apple.com/mdm/v2/assets",))
        self.assertEqual(kwargs, {'params': {'adamId': 'yolo', 'pricingParam': 'fomo'}})

    def test_get_asset_not_found(self):
        client, _ = self._get_client({"assets": []}, True)
        self.assertIsNone(client.get_asset("yolo", "fomo"))

    # iter_assets

    def test_iter_assets_data_updated_error(self):
        client, _ = self._get_client(
            [{"versionId": "1",
              "assets": [{"un": 1}],
              "nextPageIndex": 1},
             {"versionId": "2",
              "assets": [{"deux": 2}]}],
            True
        )
        with self.assertRaises(FetchedDataUpdatedError):
            list(client.iter_assets())

    def test_iter_assets_pagination_error(self):
        client, _ = self._get_client(
            [{"versionId": "1",
              "assets": [{"un": 1}],
              "nextPageIndex": 2},
             {"versionId": "2",
              "assets": [{"deux": 2}]}],
            True
        )
        with self.assertRaises(ValueError):
            list(client.iter_assets())

    def test_iter_assets_ok(self):
        client, _ = self._get_client(
            [{"versionId": "2",
              "assets": [{"un": 1}],
              "nextPageIndex": 1},
             {"versionId": "2",
              "assets": [{"deux": 2}]}],
            True
        )
        self.assertEqual(list(client.iter_assets()), [{"un": 1}, {"deux": 2}])

    # get_asset_metadata

    def test_get_asset_metadata_bad_service_config(self):
        client, _ = self._get_client({}, True)
        self.assertIsNone(client.get_asset_metadata("yolo"))

    @patch("zentral.contrib.mdm.apps_books.requests")
    def test_get_asset_metadata_empty(self, requests):
        resp = Mock()
        resp.raise_for_status.side_effect = Exception
        requests.get.return_value = resp
        client, location = self._get_client({"urls": {"contentMetadataLookup": "https://www.example.com"}}, True)
        self.assertIsNone(client.get_asset_metadata("yolo"))
        self.assertEqual(len(requests.get.call_args_list), 1)
        args, kwargs = requests.get.call_args_list[0]
        self.assertEqual(args, ("https://www.example.com",))
        self.assertEqual(kwargs["cookies"], {"itvt": location.get_server_token()})

    @patch("zentral.contrib.mdm.apps_books.requests")
    def test_get_asset_metadata_ok(self, requests):
        resp = Mock()
        resp.json.return_value = {"results": {"yolo": {"ok": True}}}
        requests.get.return_value = resp
        client, location = self._get_client({"urls": {"contentMetadataLookup": "https://www.example.com"}}, True)
        self.assertEqual(client.get_asset_metadata("yolo"), {"ok": True})

    # iter_asset_device_assignments

    def test_iter_asset_device_assignments_data_updated_error(self):
        client, _ = self._get_client(
            [{"versionId": "1",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "un"}],
              "nextPageIndex": 1},
             {"versionId": "2",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "deux"}]}],
            True
        )
        with self.assertRaises(FetchedDataUpdatedError):
            list(client.iter_asset_device_assignments("yolo", "fomo"))

    def test_iter_asset_device_assignments_pagination_error(self):
        client, _ = self._get_client(
            [{"versionId": "2",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "un"}],
              "nextPageIndex": 2},
             {"versionId": "2",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "deux"}]}],
            True
        )
        with self.assertRaises(ValueError):
            list(client.iter_asset_device_assignments("yolo", "fomo"))

    def test_iter_asset_device_assignments_ok(self):
        client, _ = self._get_client(
            [{"versionId": "2",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "un"}],
              "nextPageIndex": 1},
             {"versionId": "2",
              "assignments": [{"pricingParam": "fomo",
                               "serialNumber": "deux"},
                              {"pricingParam": "haha",
                               "serialNumber": "trois"},
                              {"pricingParam": "fomo"}]}],
            True
        )
        self.assertEqual(list(client.iter_asset_device_assignments("yolo", "fomo")), ["un", "deux"])

    # post_device_associations

    def test_post_device_associations_no_event_id(self):
        client, _ = self._get_client({}, True)
        with self.assertRaises(AppsBooksAPIError) as cm:
            client.post_device_associations("un", [("yolo", "STDQ")])
        self.assertEqual(cm.exception.args[0], "No event id")

    def test_post_device_associations(self):
        event_id = str(uuid.uuid4())
        client, _ = self._get_client({"eventId": event_id}, True)
        self.assertEqual(client.post_device_associations("un", [("yolo", "STDQ")]), event_id)
        self.assertEqual(len(client.session.post.call_args_list), 1)
        args, kwargs = client.session.post.call_args_list[0]
        self.assertEqual(args, ("https://vpp.itunes.apple.com/mdm/v2/assets/associate",))
        self.assertEqual(kwargs["json"],
                         {"assets": [{"adamId": "yolo", "pricingParam": "STDQ"}],
                          "serialNumbers": ["un"]})

    # post_device_disassociation

    def test_post_device_disassociation(self):
        client, _ = self._get_client({"ok": True}, True)
        asset = Mock(adam_id="yolo", pricing_param="fomo")
        self.assertEqual(client.post_device_disassociation("un", asset), {"ok": True})
        self.assertEqual(len(client.session.post.call_args_list), 1)
        args, kwargs = client.session.post.call_args_list[0]
        self.assertEqual(args, ("https://vpp.itunes.apple.com/mdm/v2/assets/disassociate",))
        self.assertEqual(kwargs["json"],
                         {"assets": [{"adamId": "yolo", "pricingParam": "fomo"}],
                          "serialNumbers": ["un"]})

    # LocationCache

    def test_location_cache_ok(self):
        _, location = self._get_client({"ok": True}, True)
        stc = LocationCache()
        st, c = stc.get(location.mdm_info_id)
        self.assertEqual(st, location)
        self.assertEqual(c.location, location)
        # cached response
        st2, c2 = stc.get(location.mdm_info_id)
        self.assertTrue(st is st2)
        self.assertTrue(c is c2)
        # string call
        st3, c3 = stc.get(str(location.mdm_info_id))
        self.assertTrue(st is st3)
        self.assertTrue(c is c3)

    def test_location_cache_key_error(self):
        stc = LocationCache()
        with self.assertRaises(KeyError):
            stc.get(uuid.uuid4())

    def test_lazy_location_cache_ok(self):
        _, location = self._get_client({"ok": True}, True)
        st, c = location_cache.get(location.mdm_info_id)
        self.assertEqual(st, location)
        self.assertEqual(c.location, location)
