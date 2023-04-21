from django.test import SimpleTestCase
from zentral.utils.terraform import quote


class TerraformTestCase(SimpleTestCase):
    def test_empty(self):
        self.assertEqual('""', quote(""))

    def test_simple(self):
        self.assertEqual('"été"', quote("été"))

    def test_escape_new_line(self):
        self.assertEqual(r'"été\n$%\ndeux"', quote("été\n$%\ndeux"))

    def test_escape_quote(self):
        self.assertEqual(r'"\"été\""', quote('"été"'))

    def test_special_espace_sequences(self):
        self.assertEqual(r'"$${un%%{deux%"', quote("${un%{deux%"))
