from django.test import SimpleTestCase
from zentral.utils.certificates import parse_apple_dev_id


class CertificatesTestCate(SimpleTestCase):
    def test_dev_id_match(self):
        self.assertEqual(
            parse_apple_dev_id("Developer ID Application: Mozilla Corporation (43AQ936H96)"),
            ('Mozilla Corporation', '43AQ936H96')
        )

    def test_dev_id_no_match(self):
        with self.assertRaises(ValueError) as cm:
            parse_apple_dev_id("le temps des cerises")
        self.assertEqual(cm.exception.args[0], "Not an Apple developer ID")
