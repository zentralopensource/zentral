import geoip2.models


def get_geoip2_city():
    raw = {
        "city": {
            "names": {"en": "Yolo"},
        },
        "continent": {
            "code": "NA",
            "geoname_id": 42,
            "names": {"en": "North America"},
        },
        "country": {
            "geoname_id": 1,
            "iso_code": "US",
            "names": {"en": "United States of America"},
        },
        "location": {
            "average_income": 24626,
            "accuracy_radius": 1500,
            "latitude": 44.98,
            "longitude": 93.2636,
            "metro_code": 765,
            "population_density": 1341,
            "time_zone": "America/Chicago",
        },
        "registered_country": {
            "geoname_id": 2,
            "iso_code": "CA",
            "names": {"en": "Canada"},
        },
        "subdivisions": [
            {
                "confidence": 88,
                "geoname_id": 574635,
                "iso_code": "MN",
                "names": {"en": "Minnesota"},
            },
            {
                "geoname_id": 123,
                "iso_code": "HP",
                "names": {"en": "Hennepin"},
            },
        ],
        "traits": {
            "ip_address": "1.2.3.4",
            "is_satellite_provider": True,
        },
    }
    return geoip2.models.City(["en"], **raw)
