from django.test import SimpleTestCase
from zentral.contrib.inventory.templatetags.inventory_extras import (base_inventory_tag,
                                                                     base_machine_type_icon,
                                                                     base_machine_platform_icon)


class InventoryExtrasTestCase(SimpleTestCase):
    def test_base_inventory_tag(self):
        for display_name, color, result in (
            ('yolo', '000',
             '<span class="badge" style="background-color:#000;color:#FFF">yolo</span>'),
            ('<a', 'FFFFFF',
             '<span class="badge" style="background-color:#FFFFFF;color:#000;border:1px solid grey">&lt;a</span>'),
            ('<a', 'abc',
             '<span class="badge" style="background-color:#abc;color:#000">&lt;a</span>'),
            ('Z', '<script></script>',
             '<span class="badge" style="background-color:#FFFFFF;color:#000;border:1px solid grey">Z</span>'),
        ):
            self.assertEqual(base_inventory_tag(display_name, color), result)

    def test_base_machine_type_icon(self):
        for machine_type, result in (('DESKTOP', '<i class="bi bi-pc-display"></i>'),
                                     ('EC2', '<i class="bi bi-amazon"></i>'),
                                     ('LAPTOP', '<i class="bi bi-laptop"></i>'),
                                     ('MOBILE', '<i class="bi bi-phone-fill"></i>'),
                                     ('SERVER', '<i class="bi bi-hdd-stack-fill"></i>'),
                                     ('TABLET', '<i class="bi bi-tablet-fill"></i>'),
                                     ('TV', '<i class="bi bi-tv"></i>'),
                                     ('VM', '<i class="bi bi-box"></i>'),
                                     ('<script></script>', ''),):
            self.assertEqual(base_machine_type_icon(machine_type), result)

    def test_base_machine_platform_icon(self):
        for machine_platform, result in (('IOS', '<i class="bi bi-apple" aria-hidden="true"></i>'),
                                         ('IPADOS', '<i class="bi bi-apple" aria-hidden="true"></i>'),
                                         ('MACOS', '<i class="bi bi-apple" aria-hidden="true"></i>'),
                                         ('TVOS', '<i class="bi bi-apple" aria-hidden="true"></i>'),
                                         ('LINUX', '<i class="bi bi-ubuntu" aria-hidden="true"></i>'),
                                         ('WINDOWS', '<i class="bi bi-windows" aria-hidden="true"></i>'),
                                         ('ANDROID', '<i class="bi bi-android" aria-hidden="true"></i>'),):
            self.assertEqual(base_machine_platform_icon(machine_platform), result)
