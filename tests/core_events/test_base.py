from django.test import TestCase
from zentral.core.events.base import EventRequest, EventRequestGeo, EventRequestUser, render_notification_part
from .utils import get_geoip2_city


class EventBaseTestCase(TestCase):
    def test_event_request_str(self):
        er = EventRequest(
            "user_agent" * 10,
            "192.168.1.1",
            EventRequestUser(
                id=17,
                username="yolo",
                email="fomo@example.com",
                is_remote=True,
                is_service_account=False,
                is_superuser=True,
            )
        )
        self.assertEqual(str(er), "yolo - 192.168.1.1 - user_agentuser_agentuser_agentuser_agentuser_agen…")

    def test_event_request_geo_serialization(self):
        erg = EventRequestGeo.build_from_city(get_geoip2_city())
        self.assertEqual(
            erg.serialize(),
            {'city_name': 'Yolo',
             'continent_name': 'North America',
             'country_iso_code': 'US',
             'country_name': 'United States of America',
             'location': {'lat': 44.98, 'lon': 93.2636},
             'region_iso_code': 'HP',
             'region_name': 'Hennepin'},
        )

    def test_event_request_geo_str(self):
        erg = EventRequestGeo.build_from_city(get_geoip2_city())
        self.assertEqual(erg.short_repr(), "Yolo, United States of America")

    def test_render_notification_part_missing_template(self):
        self.assertEqual(
            render_notification_part({}, "zentral_login", "yolo"),
            "Missing template event_type: zentral_login part: yolo",
        )
