from django.test import SimpleTestCase
from base.templatetags.base_extras import prettydescription


class BaseExtrasTestCase(SimpleTestCase):
    def test_prettydescription(self):
        for value, result in (
            ('yolo', '<p>yolo</p>'),
            ('<script>', '<p>&lt;script&gt;</p>'),
            ('<a>yolo\nhttp://t.co',
             '<p>&lt;a&gt;yolo<br><a href="http://t.co" rel="nofollow">http://t.co</a></p>'),
            ('<a>yolo\nhttp://<script>.co',
             '<p>&lt;a&gt;yolo<br>http://&lt;script&gt;.co</p>'),
        ):
            self.assertEqual(prettydescription(value), result)
