from django.test import SimpleTestCase
from zentral.utils.terraform import make_terraform_quoted_str


class TerraformTestCase(SimpleTestCase):
    def test_empty(self):
        self.assertEqual('""', make_terraform_quoted_str(""))

    def test_simple(self):
        self.assertEqual('"été"', make_terraform_quoted_str("été"))

    def test_escape_new_line(self):
        self.assertEqual(r'"été\n$%\ndeux"', make_terraform_quoted_str("été\n$%\ndeux"))

    def test_escape_quote(self):
        self.assertEqual(r'"\"été\""', make_terraform_quoted_str('"été"'))

    def test_special_espace_sequences(self):
        self.assertEqual(r'"$${un%%{deux%"', make_terraform_quoted_str("${un%{deux%"))
