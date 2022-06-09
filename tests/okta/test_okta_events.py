from unittest.mock import patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.okta.models import EventHook
from zentral.contrib.okta.events import post_okta_events, OktaUserSessionStart, OktaUserSessionEnd


class OktaEventTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.event_hook = EventHook.objects.create(
            okta_domain="dev-xxxxx.oktapreview.com",
            api_token=get_random_string(12),
            okta_id=get_random_string(12),
            name=get_random_string(12),
            authorization_key=get_random_string(64)
        )

    # util

    def get_test_event(self, event_type="user.session.start"):
        return {
            'cloudEventsVersion': '0.1',
            'contentType': 'application/json',
            'data': {
               'events': [
                   {'actor': {'alternateId': 'yolo@example.com',
                              'displayName': 'Yolo Fomo',
                              'id': '0001',
                              'type': 'User'},
                    'authenticationContext': {'authenticationStep': 0,
                                              'externalSessionId': '000000000000000'},
                    'client': {'device': 'Computer',
                               'geographicalContext': {
                                   'city': 'Hamburg',
                                   'country': 'Germany',
                                   'geolocation': {'lat': 53.5668, 'lon': 10.0041},
                                   'postalCode': '20359',
                                   'state': 'Free and Hanseatic City of Hamburg'
                               },
                               'ipAddress': '192.0.2.1',
                               'ipChain': [
                                   {'geographicalContext': {
                                       'city': 'Hamburg',
                                       'country': 'Germany',
                                       'geolocation': {'lat': 53.5668, 'lon': 10.0041},
                                       'postalCode': '20148',
                                       'state': 'Free and Hanseatic City of Hamburg'},
                                       'ip': '192.0.2.1',
                                       'version': 'V4'
                                    }
                               ],
                               'userAgent': {
                                   'browser': 'FIREFOX',
                                   'os': 'Windows 10',
                                   'rawUserAgent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) '
                                                   'Gecko/20100101 Firefox/102.0'
                                },
                               'zone': 'null'
                               },
                    'debugContext': {'debugData': {'deviceFingerprint': '000000000000000000000000',
                                                   'origin': 'https://dev-xxxxx.oktapreview.com',
                                                   'requestId': '0000000000000000000000000000',
                                                   'requestUri': '/api/v1/authn',
                                                   'targetEventHookIds': '000000000000000000',
                                                   'threatSuspected': 'false',
                                                   'url': '/api/v1/authn?'}},
                    'displayMessage': 'User login to Okta',
                    'eventType': event_type,
                    'legacyEventType': 'core.user_auth.login_success',
                    'outcome': {'result': 'SUCCESS'},
                    'published': '2022-06-09T06:29:21.068Z',
                    'securityContext': {'asNumber': 64496,
                                        'asOrg': 'Test',
                                        'domain': 'example.com',
                                        'isProxy': False,
                                        'isp': 'Test'},
                    'severity': 'INFO',
                    'transaction': {'detail': {},
                                    'id': '0000000000000000000000000000',
                                    'type': 'WEB'},
                    'uuid': '7c494171-b15d-4cbf-805c-d3810045aa2a',
                    'version': '0'}
               ]
            },
            'eventId': '230ab193-b5ab-4d62-ac63-9a416e213c76',
            'eventTime': '2022-06-09T06:29:31.179Z',
            'eventType': 'com.okta.event_hook',
            'eventTypeVersion': '1.0',
            'source': 'https://dev-xxxxx.oktapreview.com/api/v1/eventHooks/test'
        }

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_session_start_event(self, post_event):
        post_okta_events(self.event_hook, self.get_test_event())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0][0][0]
        self.assertIsInstance(event, OktaUserSessionStart)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_session_end_event(self, post_event):
        post_okta_events(self.event_hook, self.get_test_event(event_type="user.session.end"))
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0][0][0]
        self.assertIsInstance(event, OktaUserSessionEnd)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_unknown_event(self, post_event):
        post_okta_events(self.event_hook, self.get_test_event(event_type="unknown.event"))
        self.assertEqual(len(post_event.call_args_list), 0)
