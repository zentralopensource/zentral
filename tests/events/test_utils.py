from django.test import TestCase
from zentral.core.events.utils import decode_args, encode_args


class EventUtilsTestCase(TestCase):
    def test_decode_args(self):
        for encoded, decoded in (("", [""]),
                                 (r"\\a", [r"\a"]),
                                 (r"|1|2|3||", ["", "1", "2", "3", "", ""]),
                                 (r"a\|bc|d\\e", ["a|bc", r"d\e"])):
            self.assertEqual(decode_args(encoded), decoded)

    def test_encode_args(self):
        for encoded, decoded in (("", [""]),
                                 (r"\\a", [r"\a"]),
                                 (r"|1|2|3||", ["", 1, "2", 3, "", ""]),
                                 (r"a\|bc|d\\e", ["a|bc", r"d\e"])):
            self.assertEqual(encode_args(decoded), encoded)
