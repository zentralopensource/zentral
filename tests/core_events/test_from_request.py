from unittest.mock import Mock
from django.test import RequestFactory, TestCase
from accounts.models import User
from zentral.core.events.base import EventRequest, EventRequestGeo


class EventFromRequestTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", "fomo")

    def setUp(self):
        self.factory = RequestFactory()

    # geo

    def test_geo_from_cf_headers(self):
        request = self.factory.get(
            '/',
            HTTP_CF_IPCITY='Hamburg',
            HTTP_CF_IPCONTINENT='Europe',
            HTTP_CF_IPCOUNTRY='DE',
            HTTP_CF_IPLATITUDE='53.551086',
            HTTP_CF_IPLONGITUDE='9.993682',
            HTTP_CF_REGION='Hamburg',
        )
        geo = EventRequestGeo.build_from_request(request)
        self.assertEqual(
            geo.serialize(),
            {'city_name': 'Hamburg',
             'continent_name': 'Europe',
             'country_iso_code': 'DE',
             'location': {'lat': 53.551086, 'lon': 9.993682},
             'region_name': 'Hamburg'}
        )

    def test_geo_no_cf_headers(self):
        request = self.factory.get('/')
        self.assertIsNone(EventRequestGeo.build_from_request(request))

    def test_geo_missing_error_cf_headers(self):
        request = self.factory.get(
            '/',
            HTTP_CF_IPCITY='Hamburg',
            # HTTP_CF_IPCONTINENT='Europe',  # Missing
            HTTP_CF_IPCOUNTRY='DE',
            HTTP_CF_IPLATITUDE='53.551086',
            HTTP_CF_IPLONGITUDE='ABCD',  # Error
            HTTP_CF_REGION='Hamburg',
        )
        geo = EventRequestGeo.build_from_request(request)
        self.assertEqual(
            geo.serialize(),
            {'city_name': 'Hamburg',
             'country_iso_code': 'DE',
             'location': {'lat': 53.551086},
             'region_name': 'Hamburg'}
        )

    # full

    def test_request_from_request(self):
        request = self.factory.get(
            '/',
            HTTP_CF_IPCITY='Hamburg',
            HTTP_CF_IPCONTINENT='Europe',
            HTTP_CF_IPCOUNTRY='DE',
            HTTP_CF_IPLATITUDE='53.551086',
            HTTP_CF_IPLONGITUDE='9.993682',
            HTTP_CF_REGION='Hamburg',
        )
        request.user = self.user
        request.session = Mock()
        request.session.get_expire_at_browser_close.return_value = True
        request.session.mfa_authenticated = True
        event_req = EventRequest.build_from_request(request)
        self.assertEqual(
            event_req.serialize(),
            {'geo': {'city_name': 'Hamburg',
                     'continent_name': 'Europe',
                     'country_iso_code': 'DE',
                     'location': {'lat': 53.551086, 'lon': 9.993682},
                     'region_name': 'Hamburg'},
             'ip': '127.0.0.1',
             'method': 'GET',
             'path': '/',
             'user': {'email': 'godzilla@zentral.io',
                      'id': self.user.pk,
                      'is_remote': False,
                      'is_service_account': False,
                      'is_superuser': False,
                      'session': {'expire_at_browser_close': True,
                                  'is_remote': False,
                                  'mfa_authenticated': True,
                                  'token_authenticated': False},
                      'username': 'godzilla'}}
        )
