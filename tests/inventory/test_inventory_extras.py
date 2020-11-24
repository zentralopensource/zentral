from django.test import SimpleTestCase
from zentral.contrib.inventory.templatetags.inventory_extras import (base_inventory_tag,
                                                                     base_machine_type_icon,
                                                                     sha_256_link)


class InventoryExtrasTestCase(SimpleTestCase):
    def test_base_inventory_tag(self):
        for display_name, color, result in (
            ('yolo', '000',
             '<span class="label" style="background-color:#000;color:#FFF">yolo</span>'),
            ('<a', 'FFFFFF',
             '<span class="label" style="background-color:#FFFFFF;color:#000;border:1px solid grey">&lt;a</span>'),
            ('<a', 'abc',
             '<span class="label" style="background-color:#abc;color:#000">&lt;a</span>'),
            ('Z', '<script></script>',
             '<span class="label" style="background-color:#FFFFFF;color:#000;border:1px solid grey">Z</span>'),
        ):
            self.assertEqual(base_inventory_tag(display_name, color), result)

    def test_base_machine_type_icon(self):
        for machine_type, result in (('VM', '<i class="fas fa-cube"></i>'),
                                     ('TV', '<i class="fas fa-tv"></i>'),
                                     ('<script></script>', ''),):
            self.assertEqual(base_machine_type_icon(machine_type), result)

    def test_sha_256_link(self):
        self.assertEqual(sha_256_link(""), '-')
        self.assertEqual(sha_256_link("<script></script>"), '-')
        sha_256 = 64 * "f"
        self.assertEqual(
            sha_256_link(sha_256),
            f'<a href="/inventory/macos_apps/?sha_256={sha_256}">{sha_256}</a>'
        )
