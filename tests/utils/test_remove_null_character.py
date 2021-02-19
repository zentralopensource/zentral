from django.test import SimpleTestCase
from zentral.utils.json import remove_null_character


class RemoveNULLTestCase(SimpleTestCase):
    def test_all(self):
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
