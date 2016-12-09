from django.test import SimpleTestCase
from zentral.utils.dict import dict_diff


class DictDiffTestCase(SimpleTestCase):
    def test_empty_diff(self):
        self.assertEqual(dict_diff({}, {}), {})

    def test_none(self):
        self.assertEqual(dict_diff({}, {"archived_at": None}), {})

    def test_val_diff(self):
        self.assertEqual(dict_diff({}, {"un": 1}), {"un": {"added": 1}})
        self.assertEqual(dict_diff({"un": 1}, {}), {"un": {"removed": 1}})
        self.assertEqual(dict_diff({"un": 1}, {"un": 2}),
                         {"un": {"removed": 1,
                                 "added": 2}})

    def test_list_diff(self):
        self.assertEqual(dict_diff({}, {"un": [1]}),
                         {"un": {"added": [1]}})
        self.assertEqual(dict_diff({"un": [1]}, {}),
                         {"un": {"removed": [1]}})
        self.assertEqual(dict_diff({"un": [1]}, {"un": [2]}),
                         {"un": {"removed": [1],
                                 "added": [2]}})

    def test_all_in_one(self):
        self.assertEqual(dict_diff({"un": 1,
                                    "list": [{"un": 1}, {"deux": 2}],
                                    "str": "ha!"},
                                   {"list": [{"deux": 2}, {"trois": 3}],
                                    "str": "ha!"}),
                         {"un": {"removed": 1},
                          "list": {"removed": [{"un": 1}],
                                   "added": [{"trois": 3}]}})
