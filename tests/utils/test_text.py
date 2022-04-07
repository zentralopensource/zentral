from django.test import SimpleTestCase
from zentral.utils.text import decode_args, encode_args


class TextTestCase(SimpleTestCase):
    def test_decode_assertion_error(self):
        with self.assertRaises(AssertionError) as e:
            decode_args("", delimiter="y", escapechar="y")
        assertion_error = e.exception
        self.assertEqual(assertion_error.args[0], "delimiter and escapechar must be different")

    def test_encode_assertion_error(self):
        with self.assertRaises(AssertionError) as e:
            encode_args([], delimiter="y", escapechar="y")
        assertion_error = e.exception
        self.assertEqual(assertion_error.args[0], "delimiter and escapechar must be different")

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
