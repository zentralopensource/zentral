from datetime import datetime
from django.test import SimpleTestCase
from zentral.utils.json import prepare_loaded_plist, remove_null_character


class JsonUtilsTestCase(SimpleTestCase):
    def test_prepare_loaded_plist(self):
        self.assertEqual(
            prepare_loaded_plist({"un": b"un",
                                  "deux": 2,
                                  "trois": {1, 2, 3},
                                  4: ["1\u0000", b"deux", 3],
                                  "cinq": [{5: True,
                                            6: datetime(2000, 1, 1)}]}),
            {"un": "dW4=",
             "deux": 2,
             "trois": {1, 2, 3},
             4: ["1", "ZGV1eA==", 3],
             "cinq": [{5: True, 6: '2000-01-01T00:00:00'}]}
        )

    def test_remove_null_character(self):
        self.assertEqual(
            remove_null_character({"un": "1\u0000",
                                   "deux": 2,
                                   "trois": {1, 2, 3},
                                   4: [1, "de\u0000ux", 3],
                                   "cinq": [{5: True}]}),
            {"un": "1",
             "deux": 2,
             "trois": {1, 2, 3},
             4: [1, "deux", 3],
             "cinq": [{5: True}]}
        )
